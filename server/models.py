"""Database models for the platform (SQLAlchemy).

Defaults to SQLite so the project runs anywhere with no setup. Set
DATABASE_URL to a PostgreSQL URL to use Postgres instead (as in the proposal).
"""
from __future__ import annotations

import datetime as dt
import os

from sqlalchemy import (create_engine, Column, Integer, String, Boolean, Text,
                        DateTime, ForeignKey)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


def _now():
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    verified = Column(Boolean, default=False)
    confirm_token = Column(String(64))  # emailed link token; cleared on confirm
    created_at = Column(DateTime, default=_now)

    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    repo = Column(String(255))
    token_hash = Column(String(64), nullable=False)   # sha256 of the project token
    token_prefix = Column(String(12))                 # shown in UI to identify it
    created_at = Column(DateTime, default=_now)

    owner = relationship("User", back_populates="projects")
    runs = relationship("ScanRun", back_populates="project")


class VerifiedDomain(Base):
    """A domain the owner proved control of, for Phase 2 (agent mode)."""
    __tablename__ = "verified_domains"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    host = Column(String(255), nullable=False)
    challenge = Column(String(64), nullable=False)  # TXT value: apiscanner-verify=<challenge>
    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime)
    created_at = Column(DateTime, default=_now)


class AgentKey(Base):
    __tablename__ = "agent_keys"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    key_hash = Column(String(64), nullable=False)
    key_prefix = Column(String(12))
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)


class ScanJob(Base):
    """A queued job the agent polls for (Phase 2)."""
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target = Column(String(500), nullable=False)
    status = Column(String(20), default="queued")  # queued | taken | done | refused
    created_at = Column(DateTime, default=_now)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target = Column(String(500))
    mode = Column(String(10))  # "ci" | "agent"
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    ok = Column(Integer, default=0)
    findings_json = Column(Text)
    created_at = Column(DateTime, default=_now)

    project = relationship("Project", back_populates="runs")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    project_id = Column(Integer)
    action = Column(String(60), nullable=False)
    target = Column(String(500))
    status = Column(String(20))
    ip = Column(String(64))
    detail = Column(Text)
    created_at = Column(DateTime, default=_now)


def make_engine(url: str | None = None):
    url = url or os.environ.get("DATABASE_URL", "sqlite:///platform.db")
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    return create_engine(url, **kwargs)


def init_db(engine):
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
