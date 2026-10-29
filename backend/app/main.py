"""College Notes Hub API. SQLite/local storage is intentional development fallback."""
from __future__ import annotations
import os, uuid, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, String, Integer, DateTime, ForeignKey, Text, UniqueConstraint, select, func, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
from passlib.context import CryptContext
import jwt
from supabase import create_client

ROOT = Path(__file__).resolve().parents[1]
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / '.env', extra='ignore')
    database_url: str = 'sqlite:///./college_notes.db'
    jwt_secret_key: str = 'development-only-secret-change-this-to-32-plus-characters'
    jwt_algorithm: str = 'HS256'
    access_token_expire_minutes: int = 480
    frontend_origin: str = 'http://localhost:5173'
    max_upload_size_mb: int = 10
    supabase_url: str = ''
    supabase_service_role_key: str = ''
    supabase_storage_bucket: str = 'notes'
    admin_email: str = ''
settings = Settings()
supabase = create_client(settings.supabase_url, settings.supabase_service_role_key) if settings.supabase_url and settings.supabase_service_role_key else None
db_url = settings.database_url
if db_url.startswith('sqlite:///./'): db_url = 'sqlite:///' + str(ROOT / db_url.replace('sqlite:///./',''))
engine = create_engine(db_url, connect_args={'check_same_thread': False} if db_url.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120)); branch: Mapped[str] = mapped_column(String(80)); semester: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(20), default='student'); password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow); updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
class Note(Base):
    __tablename__='notes'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(180), index=True); description: Mapped[str] = mapped_column(Text, default='')
    subject: Mapped[str] = mapped_column(String(100), index=True); branch: Mapped[str] = mapped_column(String(80), index=True); semester: Mapped[int] = mapped_column(Integer, index=True)
    academic_year: Mapped[Optional[str]] = mapped_column(String(20), nullable=True); tags: Mapped[str] = mapped_column(String(500), default='')
    original_filename: Mapped[str] = mapped_column(String(255)); storage_path: Mapped[str] = mapped_column(String(500)); file_type: Mapped[str] = mapped_column(String(30)); file_size: Mapped[int] = mapped_column(Integer)
    uploader_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True); status: Mapped[str] = mapped_column(String(20), default='pending', index=True); download_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow); updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    uploader = relationship(User)
class Bookmark(Base):
    __tablename__='bookmarks'; __table_args__=(UniqueConstraint('user_id','note_id', name='uq_bookmark'),)
    id: Mapped[int] = mapped_column(primary_key=True); user_id: Mapped[str] = mapped_column(ForeignKey('users.id')); note_id: Mapped[str] = mapped_column(ForeignKey('notes.id')); created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
# PBKDF2-SHA256 is a secure, portable password hash and avoids native bcrypt
# build incompatibilities on newer Python versions.
pwd = CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto')
def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def token_for(user: User): return jwt.encode({'sub':user.id,'exp':datetime.now(timezone.utc)+timedelta(minutes=settings.access_token_expire_minutes)}, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
def current_user(authorization: Optional[str] = None, db: Session = Depends(get_db),):
    # Header is read explicitly below because FastAPI dependency defaults cannot infer it.
    raise RuntimeError
from fastapi import Header
def require_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401,'Authentication required')
    try: user_id=jwt.decode(authorization[7:],settings.jwt_secret_key,algorithms=[settings.jwt_algorithm])['sub']
    except jwt.PyJWTError: raise HTTPException(401,'Session is invalid or expired')
    user=db.get(User,user_id)
    if not user: raise HTTPException(401,'Session is invalid')
    return user
def optional_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization: return None
    return require_user(authorization, db)
def require_admin(user: User = Depends(require_user)):
    if user.role!='admin': raise HTTPException(403,'Administrator access required')
    return user
class Register(BaseModel): full_name:str=Field(min_length=2,max_length=120); email:EmailStr; password:str=Field(min_length=8,max_length=100); branch:str=Field(min_length=2,max_length=80); semester:int=Field(ge=1,le=12)
class Login(BaseModel): email:EmailStr; password:str
class ProfileUpdate(BaseModel): full_name:Optional[str]=Field(None,min_length=2,max_length=120); branch:Optional[str]=Field(None,min_length=2,max_length=80); semester:Optional[int]=Field(None,ge=1,le=12)
class StatusUpdate(BaseModel): status:str=Field(pattern='^(pending|approved|rejected)$')
app=FastAPI(title='College Notes Hub API', version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.frontend_origin.split(',')],allow_credentials=False,allow_methods=['*'],allow_headers=['*'])
@app.on_event('startup')
def start(): Base.metadata.create_all(engine); (ROOT/'uploads').mkdir(exist_ok=True)
def user_data(u:User): return {'id':u.id,'email':u.email,'full_name':u.full_name,'branch':u.branch,'semester':u.semester,'role':u.role,'created_at':u.created_at.isoformat()}
def note_data(n:Note, bookmarked=False): return {'id':n.id,'title':n.title,'description':n.description,'subject':n.subject,'branch':n.branch,'semester':n.semester,'academic_year':n.academic_year,'tags':[x.strip() for x in n.tags.split(',') if x.strip()],'original_filename':n.original_filename,'file_type':n.file_type,'file_size':n.file_size,'status':n.status,'download_count':n.download_count,'created_at':n.created_at.isoformat(),'uploader':n.uploader.full_name,'uploader_id':n.uploader_id,'bookmarked':bookmarked}
def store_pdf(path: str, content: bytes):
    """Write to private Supabase Storage when configured, else explicit local dev storage."""
    if supabase:
        supabase.storage.from_(settings.supabase_storage_bucket).upload(path, content, {'content-type':'application/pdf','upsert':'false'})
    else:
        local=ROOT/'uploads'/path; local.parent.mkdir(parents=True,exist_ok=True); local.write_bytes(content)
def remove_pdf(path: str):
    if supabase: supabase.storage.from_(settings.supabase_storage_bucket).remove([path])
    else:
        local=ROOT/'uploads'/path
        if local.exists(): local.unlink()
@app.get('/api/health')
def health(): return {'status':'ok','storage':'supabase' if settings.supabase_url else 'local-development'}
@app.get('/api/health/db')
def health_db(db:Session=Depends(get_db)): db.execute(select(1)); return {'status':'ok','database':'configured'}
@app.post('/api/auth/register',status_code=201)
def register(data:Register,db:Session=Depends(get_db)):
    if db.scalar(select(User).where(User.email==data.email.lower())): raise HTTPException(409,'An account with this email already exists')
    role='admin' if settings.admin_email and data.email.lower()==settings.admin_email.lower() else 'student'
    u=User(email=data.email.lower(),full_name=data.full_name.strip(),branch=data.branch.strip(),semester=data.semester,role=role,password_hash=pwd.hash(data.password)); db.add(u); db.commit(); db.refresh(u)
    return {'access_token':token_for(u),'token_type':'bearer','user':user_data(u)}
@app.post('/api/auth/login')
def login(data:Login,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==data.email.lower()))
    if not u or not pwd.verify(data.password,u.password_hash): raise HTTPException(401,'Invalid email or password')
    return {'access_token':token_for(u),'token_type':'bearer','user':user_data(u)}
@app.get('/api/auth/me')
def me(u:User=Depends(require_user)): return user_data(u)
@app.get('/api/users/me')
def profile(u:User=Depends(require_user),db:Session=Depends(get_db)):
    data=user_data(u); data['total_uploads']=db.scalar(select(func.count()).select_from(Note).where(Note.uploader_id==u.id)); data['total_bookmarks']=db.scalar(select(func.count()).select_from(Bookmark).where(Bookmark.user_id==u.id)); return data
@app.patch('/api/users/me')
def update_profile(data:ProfileUpdate,u:User=Depends(require_user),db:Session=Depends(get_db)):
    for k,v in data.model_dump(exclude_none=True).items(): setattr(u,k,v)
    db.commit(); db.refresh(u); return user_data(u)
@app.get('/api/subjects')
def subjects(db:Session=Depends(get_db)): return [x[0] for x in db.execute(select(Note.subject).distinct().order_by(Note.subject)).all()]
@app.get('/api/notes')
def list_notes(q:str='',branch:str='',semester:Optional[int]=Query(None,ge=1,le=12),subject:str='',sort:str=Query('newest',pattern='^(newest|oldest|title|popularity)$'),page:int=Query(1,ge=1),limit:int=Query(12,ge=1,le=50),db:Session=Depends(get_db),u:Optional[User]=Depends(optional_user)):
    stmt=select(Note).where(Note.status=='approved')
    if q: stmt=stmt.where(or_(Note.title.ilike(f'%{q}%'),Note.description.ilike(f'%{q}%'),Note.subject.ilike(f'%{q}%'),Note.tags.ilike(f'%{q}%')))
    if branch: stmt=stmt.where(Note.branch==branch)
    if semester: stmt=stmt.where(Note.semester==semester)
    if subject: stmt=stmt.where(Note.subject==subject)
    order={'newest':Note.created_at.desc(),'oldest':Note.created_at,'title':Note.title,'popularity':Note.download_count.desc()}[sort]
    total=db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; notes=db.scalars(stmt.order_by(order).offset((page-1)*limit).limit(limit)).all()
    marked=set(db.scalars(select(Bookmark.note_id).where(Bookmark.user_id==u.id)).all()) if u else set()
    return {'items':[note_data(n,n.id in marked) for n in notes],'total':total,'page':page,'limit':limit}
@app.get('/api/notes/{note_id}')
def get_note(note_id:str,db:Session=Depends(get_db),u:Optional[User]=Depends(optional_user)):
    n=db.get(Note,note_id)
    if not n or (n.status!='approved' and (not u or (n.uploader_id!=u.id and u.role!='admin'))): raise HTTPException(404,'Note not found')
    return note_data(n,bool(u and db.scalar(select(Bookmark).where(Bookmark.user_id==u.id,Bookmark.note_id==n.id))))
@app.post('/api/notes',status_code=201)
async def create_note(title:str=Form(...),description:str=Form(''),subject:str=Form(...),branch:str=Form(...),semester:int=Form(...),academic_year:str=Form(''),tags:str=Form(''),file:UploadFile=File(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    if semester<1 or semester>12: raise HTTPException(422,'Semester must be between 1 and 12')
    if not file.filename or Path(file.filename).suffix.lower()!='.pdf' or file.content_type not in ('application/pdf','application/octet-stream'): raise HTTPException(422,'Only PDF files are accepted')
    content=await file.read(); max_bytes=settings.max_upload_size_mb*1024*1024
    if not content: raise HTTPException(422,'The selected file is empty')
    if len(content)>max_bytes: raise HTTPException(413,f'File must be under {settings.max_upload_size_mb} MB')
    if not content.startswith(b'%PDF'): raise HTTPException(422,'The uploaded file is not a valid PDF')
    storage_name=f'{u.id}/{uuid.uuid4()}.pdf'; path=ROOT/'uploads'/storage_name
    try:
        store_pdf(storage_name, content); n=Note(title=title.strip(),description=description.strip(),subject=subject.strip(),branch=branch.strip(),semester=semester,academic_year=academic_year.strip() or None,tags=tags[:500],original_filename=Path(file.filename).name,storage_path=storage_name,file_type='PDF',file_size=len(content),uploader_id=u.id); db.add(n); db.commit(); db.refresh(n)
    except Exception:
        try: remove_pdf(storage_name)
        except Exception: pass
        db.rollback(); raise HTTPException(500,'Could not save note metadata')
    return note_data(n)
@app.patch('/api/notes/{note_id}')
def edit_note(note_id:str,title:Optional[str]=Form(None),description:Optional[str]=Form(None),subject:Optional[str]=Form(None),branch:Optional[str]=Form(None),semester:Optional[int]=Form(None),tags:Optional[str]=Form(None),u:User=Depends(require_user),db:Session=Depends(get_db)):
    n=db.get(Note,note_id)
    if not n: raise HTTPException(404,'Note not found')
    if n.uploader_id!=u.id and u.role!='admin': raise HTTPException(403,'You do not own this note')
    for k,v in {'title':title,'description':description,'subject':subject,'branch':branch,'semester':semester,'tags':tags}.items():
        if v is not None: setattr(n,k,v)
    db.commit(); db.refresh(n); return note_data(n)
@app.delete('/api/notes/{note_id}',status_code=204)
def delete_note(note_id:str,u:User=Depends(require_user),db:Session=Depends(get_db)):
    n=db.get(Note,note_id)
    if not n: raise HTTPException(404,'Note not found')
    if n.uploader_id!=u.id and u.role!='admin': raise HTTPException(403,'You do not own this note')
    storage_path=n.storage_path; db.delete(n); db.commit()
    try: remove_pdf(storage_path)
    except Exception: pass
@app.get('/api/notes/{note_id}/download')
def download(note_id:str,u:User=Depends(require_user),db:Session=Depends(get_db)):
    n=db.get(Note,note_id)
    if not n or (n.status!='approved' and n.uploader_id!=u.id and u.role!='admin'): raise HTTPException(404,'Note not found')
    if supabase:
        try: url=supabase.storage.from_(settings.supabase_storage_bucket).create_signed_url(n.storage_path, 60)['signedURL']
        except Exception: raise HTTPException(404,'File is no longer available')
        n.download_count+=1; db.commit(); return RedirectResponse(url)
    path=ROOT/'uploads'/n.storage_path
    if not path.exists(): raise HTTPException(404,'File is no longer available')
    n.download_count+=1; db.commit(); return FileResponse(path,media_type='application/pdf',filename=n.original_filename)
@app.post('/api/notes/{note_id}/bookmark',status_code=201)
def bookmark(note_id:str,u:User=Depends(require_user),db:Session=Depends(get_db)):
    if not db.get(Note,note_id): raise HTTPException(404,'Note not found')
    if db.scalar(select(Bookmark).where(Bookmark.user_id==u.id,Bookmark.note_id==note_id)): return {'bookmarked':True}
    db.add(Bookmark(user_id=u.id,note_id=note_id)); db.commit(); return {'bookmarked':True}
@app.delete('/api/notes/{note_id}/bookmark',status_code=204)
def unbookmark(note_id:str,u:User=Depends(require_user),db:Session=Depends(get_db)):
    b=db.scalar(select(Bookmark).where(Bookmark.user_id==u.id,Bookmark.note_id==note_id))
    if b: db.delete(b); db.commit()
@app.get('/api/users/me/notes')
def mine(u:User=Depends(require_user),db:Session=Depends(get_db)): return [note_data(n) for n in db.scalars(select(Note).where(Note.uploader_id==u.id).order_by(Note.created_at.desc())).all()]
@app.get('/api/users/me/bookmarks')
def bookmarks(u:User=Depends(require_user),db:Session=Depends(get_db)):
    notes=db.scalars(select(Note).join(Bookmark).where(Bookmark.user_id==u.id).order_by(Bookmark.created_at.desc())).all(); return [note_data(n,True) for n in notes]
@app.get('/api/dashboard')
def dashboard(u:User=Depends(require_user),db:Session=Depends(get_db)):
    approved=db.scalar(select(func.count()).select_from(Note).where(Note.status=='approved')) or 0; mine=db.scalar(select(func.count()).select_from(Note).where(Note.uploader_id==u.id)) or 0; saved=db.scalar(select(func.count()).select_from(Bookmark).where(Bookmark.user_id==u.id)) or 0
    recent=db.scalars(select(Note).where(Note.status=='approved').order_by(Note.created_at.desc()).limit(4)).all(); return {'total_notes':approved,'my_uploads':mine,'bookmarks':saved,'recent':[note_data(n) for n in recent]}
@app.get('/api/admin/stats')
def admin_stats(u:User=Depends(require_admin),db:Session=Depends(get_db)): return {'users':db.scalar(select(func.count()).select_from(User)),'notes':db.scalar(select(func.count()).select_from(Note)),'pending':db.scalar(select(func.count()).select_from(Note).where(Note.status=='pending'))}
@app.get('/api/admin/notes')
def admin_notes(u:User=Depends(require_admin),db:Session=Depends(get_db)): return [note_data(n) for n in db.scalars(select(Note).order_by(Note.created_at.desc())).all()]
@app.patch('/api/admin/notes/{note_id}/status')
def moderate(note_id:str,data:StatusUpdate,u:User=Depends(require_admin),db:Session=Depends(get_db)):
    n=db.get(Note,note_id)
    if not n: raise HTTPException(404,'Note not found')
    n.status=data.status; db.commit(); return note_data(n)
