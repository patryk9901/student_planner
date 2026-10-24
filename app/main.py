from pathlib import Path
import hashlib, hmac, os, secrets, time
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = os.getenv('DATABASE_URL')
SESSION_SECRET = os.getenv('SESSION_SECRET')
if not DATABASE_URL or not SESSION_SECRET: raise RuntimeError('DATABASE_URL and SESSION_SECRET are required')
signer = URLSafeTimedSerializer(SESSION_SECRET, salt='student-planner-session')
app = FastAPI(title='Student Planner API')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

def conn(): return psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 180000).hex()
def verify_password(password, stored):
    salt, digest = stored.split(':', 1)
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt)).split(':', 1)[1], digest)

def init_db():
    with conn() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, login VARCHAR(80) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE TABLE IF NOT EXISTS semesters (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name VARCHAR(120) NOT NULL, year VARCHAR(30) NOT NULL, active BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE TABLE IF NOT EXISTS subjects (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, semester_id INTEGER NOT NULL REFERENCES semesters(id) ON DELETE CASCADE, name VARCHAR(160) NOT NULL, teacher VARCHAR(160) DEFAULT '', color VARCHAR(20) DEFAULT '#d9f99d', grade NUMERIC);
        CREATE TABLE IF NOT EXISTS events (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE, title VARCHAR(180) NOT NULL, event_date DATE, time_from TIME, time_to TIME, event_type VARCHAR(80) NOT NULL, status VARCHAR(30) NOT NULL DEFAULT 'not_started', description TEXT DEFAULT '');
        UPDATE events SET event_date=CURRENT_DATE WHERE event_date IS NULL;
        ALTER TABLE events ALTER COLUMN event_date SET NOT NULL;
        ALTER TABLE events ADD COLUMN IF NOT EXISTS time_from TIME;
        ALTER TABLE events ADD COLUMN IF NOT EXISTS time_to TIME;
        CREATE TABLE IF NOT EXISTS audit_logs (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, method VARCHAR(10) NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());''')

@app.on_event('startup')
def startup():
    for _ in range(20):
        try: init_db(); return
        except psycopg.OperationalError: time.sleep(1)
    raise RuntimeError('PostgreSQL is unavailable')

@app.middleware('http')
async def audit_mutations(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith('/api/') and request.method in {'POST','PUT','PATCH','DELETE'} and not request.url.path.startswith('/api/auth/'):
        raw = request.cookies.get('student_planner_session')
        try:
            user_id = signer.loads(raw, max_age=2592000)['user_id'] if raw else None
            if user_id:
                with conn() as c: c.execute('INSERT INTO audit_logs(user_id,method,path,status_code) VALUES (%s,%s,%s,%s)', (user_id,request.method,request.url.path,response.status_code))
        except Exception: pass
    return response

class Credentials(BaseModel):
    login: str = Field(min_length=3, max_length=80); password: str = Field(min_length=6, max_length=128)
class RegisterIn(Credentials): email: str = Field(min_length=5, max_length=255)
class SemesterIn(BaseModel): name: str = Field(min_length=1); year: str = Field(min_length=1)
class SubjectIn(BaseModel): semester_id: int; name: str = Field(min_length=1); teacher: str = ''; color: str = '#d9f99d'; grade: float | None = None
class EventIn(BaseModel): subject_id: int; title: str = Field(min_length=1); event_date: str; time_from: str | None = None; time_to: str | None = None; event_type: str = 'Zadanie'; status: str = 'not_started'; description: str = ''

def current_user(request: Request):
    raw = request.cookies.get('student_planner_session')
    if not raw: raise HTTPException(401, 'Zaloguj się')
    try: data = signer.loads(raw, max_age=2592000)
    except BadSignature: raise HTTPException(401, 'Sesja wygasła')
    with conn() as c: user = c.execute('SELECT id,login,email FROM users WHERE id=%s', (data['user_id'],)).fetchone()
    if not user: raise HTTPException(401, 'Nieprawidłowa sesja')
    return user

@app.post('/api/auth/register')
def register(p: RegisterIn, response: Response):
    with conn() as c:
        try: row = c.execute('INSERT INTO users(login,email,password_hash) VALUES (%s,%s,%s) RETURNING id,login,email', (p.login.strip(),p.email.strip().lower(),hash_password(p.password))).fetchone()
        except psycopg.errors.UniqueViolation: raise HTTPException(409, 'Login lub email jest już zajęty')
    response.set_cookie('student_planner_session', signer.dumps({'user_id':row['id']}), httponly=True, samesite='lax', max_age=2592000)
    return row
@app.post('/api/auth/login')
def login(p: Credentials, response: Response):
    with conn() as c: row = c.execute('SELECT id,login,email,password_hash FROM users WHERE login=%s', (p.login.strip(),)).fetchone()
    if not row or not verify_password(p.password,row['password_hash']): raise HTTPException(401,'Nieprawidłowy login lub hasło')
    response.set_cookie('student_planner_session', signer.dumps({'user_id':row['id']}), httponly=True, samesite='lax', max_age=2592000)
    return {'id':row['id'],'login':row['login'],'email':row['email']}
@app.post('/api/auth/logout')
def logout(response: Response): response.delete_cookie('student_planner_session'); return {'ok':True}
@app.get('/api/auth/me')
def me(user=Depends(current_user)): return user

@app.get('/api/overview')
def overview(semester_id:int|None=None, user=Depends(current_user)):
    with conn() as c:
        sems=c.execute('SELECT * FROM semesters WHERE user_id=%s ORDER BY id DESC',(user['id'],)).fetchall(); selected=semester_id or next((s['id'] for s in sems if s['active']),sems[0]['id'] if sems else None)
        if selected: c.execute('UPDATE semesters SET active=(id=%s) WHERE user_id=%s',(selected,user['id']))
        subjects=[]
        for s in c.execute('SELECT * FROM subjects WHERE user_id=%s AND semester_id=%s ORDER BY id',(user['id'],selected or -1)).fetchall():
            item=dict(s); item['events']=c.execute('SELECT * FROM events WHERE user_id=%s AND subject_id=%s ORDER BY event_date',(user['id'],s['id'])).fetchall(); done=sum(e['status']=='done' for e in item['events']); item['progress']=round(done/len(item['events'])*100) if item['events'] else 0; subjects.append(item)
    return {'semesters':sems,'selected_semester_id':selected,'subjects':subjects}

@app.post('/api/semesters')
def create_semester(p:SemesterIn,user=Depends(current_user)):
    with conn() as c: return c.execute('INSERT INTO semesters(user_id,name,year) VALUES (%s,%s,%s) RETURNING *',(user['id'],p.name,p.year)).fetchone()
@app.put('/api/semesters/{sid}')
def update_semester(sid:int,p:SemesterIn,user=Depends(current_user)):
    with conn() as c: c.execute('UPDATE semesters SET name=%s,year=%s WHERE id=%s AND user_id=%s',(p.name,p.year,sid,user['id'])); return {'ok':True}
@app.delete('/api/semesters/{sid}')
def delete_semester(sid:int,user=Depends(current_user)):
    with conn() as c: c.execute('DELETE FROM semesters WHERE id=%s AND user_id=%s',(sid,user['id'])); return {'ok':True}

@app.post('/api/subjects')
def create_subject(p:SubjectIn,user=Depends(current_user)):
    with conn() as c: return c.execute('INSERT INTO subjects(user_id,semester_id,name,teacher,color,grade) SELECT %s,id,%s,%s,%s,%s FROM semesters WHERE id=%s AND user_id=%s RETURNING *',(user['id'],p.name,p.teacher,p.color,p.grade,p.semester_id,user['id'])).fetchone()
@app.put('/api/subjects/{sid}')
def update_subject(sid:int,p:SubjectIn,user=Depends(current_user)):
    with conn() as c: c.execute('UPDATE subjects SET name=%s,teacher=%s,color=%s,grade=%s WHERE id=%s AND user_id=%s',(p.name,p.teacher,p.color,p.grade,sid,user['id'])); return {'ok':True}
@app.delete('/api/subjects/{sid}')
def delete_subject(sid:int,user=Depends(current_user)):
    with conn() as c: c.execute('DELETE FROM subjects WHERE id=%s AND user_id=%s',(sid,user['id'])); return {'ok':True}

@app.post('/api/events')
def create_event(p:EventIn,user=Depends(current_user)):
    with conn() as c: return c.execute('INSERT INTO events(user_id,subject_id,title,event_date,time_from,time_to,event_type,status,description) SELECT %s,id,%s,%s,%s,%s,%s,%s,%s FROM subjects WHERE id=%s AND user_id=%s RETURNING *',(user['id'],p.title,p.event_date,p.time_from,p.time_to,p.event_type,p.status,p.description,p.subject_id,user['id'])).fetchone()
@app.put('/api/events/{eid}')
def update_event(eid:int,p:EventIn,user=Depends(current_user)):
    with conn() as c: c.execute('UPDATE events SET subject_id=%s,title=%s,event_date=%s,time_from=%s,time_to=%s,event_type=%s,status=%s,description=%s WHERE id=%s AND user_id=%s',(p.subject_id,p.title,p.event_date,p.time_from,p.time_to,p.event_type,p.status,p.description,eid,user['id'])); return {'ok':True}
@app.delete('/api/events/{eid}')
def delete_event(eid:int,user=Depends(current_user)):
    with conn() as c: c.execute('DELETE FROM events WHERE id=%s AND user_id=%s',(eid,user['id'])); return {'ok':True}

app.mount('/static', StaticFiles(directory=BASE_DIR/'static'), name='static')
@app.get('/')
def index(): return FileResponse(BASE_DIR/'static'/'index.html')
