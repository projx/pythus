from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean, JSON, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json

Base = declarative_base()

class Monitor(Base):
    __tablename__ = 'monitors'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    group = Column(String, nullable=False)
    url = Column(String, nullable=False)
    config = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    checks = relationship("Check", back_populates="monitor", cascade="all, delete-orphan")
    response_times = relationship("ResponseTime", back_populates="monitor", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="monitor", cascade="all, delete-orphan")

class Check(Base):
    __tablename__ = 'checks'
    
    id = Column(Integer, primary_key=True)
    monitor_id = Column(Integer, ForeignKey('monitors.id'), nullable=False)
    check_type = Column(String, nullable=False)
    success = Column(Boolean, nullable=False)
    message = Column(String)
    details = Column(JSON)
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    
    # Relationships
    monitor = relationship("Monitor", back_populates="checks")

class ResponseTime(Base):
    __tablename__ = 'response_times'
    
    id = Column(Integer, primary_key=True)
    monitor_id = Column(Integer, ForeignKey('monitors.id'), nullable=False)
    response_time = Column(Float, nullable=False)  # in milliseconds
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    
    # Relationships
    monitor = relationship("Monitor", back_populates="response_times")

class Log(Base):
    __tablename__ = 'logs'
    
    id = Column(Integer, primary_key=True)
    monitor_id = Column(Integer, ForeignKey('monitors.id'), nullable=False)
    level = Column(String, nullable=False)  # 'INFO', 'WARNING', 'ERROR'
    message = Column(String, nullable=False)
    details = Column(JSON)
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    
    # Relationships
    monitor = relationship("Monitor", back_populates="logs")


# Database setup
def init_db():
    """Initialize the database and create tables."""
    # Create SQLite database engine
    engine = create_engine('sqlite:///pythus.db')
    
    # Create all tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Create session factory
    Session = sessionmaker(bind=engine)
    return Session

# Helper functions for database operations
class DatabaseManager:
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def get_or_create_monitor(self, name: str, group: str, url: str, config: dict) -> int:
        """Get existing monitor or create a new one."""
        with self.session_factory() as session:
            monitor = session.query(Monitor).filter_by(name=name).first()
            if monitor is None:
                monitor = Monitor(
                    name=name,
                    group=group,
                    url=url,
                    config=config,
                    created_at=datetime.now()
                )
                session.add(monitor)
                session.commit()
            return monitor.id

    def add_monitor(self, name: str, group: str, url: str, config: dict) -> int:
        """Add a new monitor or update existing one."""
        return self.get_or_create_monitor(name, group, url, config)

    def add_check_result(self, monitor_id: int, check_type: str, success: bool, message: str, details: dict = None):
        with self.session_factory() as session:
            check = Check(
                monitor_id=monitor_id,
                check_type=check_type,
                success=success,
                message=message,
                details=details
            )
            session.add(check)
            session.commit()
    
    def add_response_time(self, monitor_id: int, response_time: float):
        with self.session_factory() as session:
            rt = ResponseTime(
                monitor_id=monitor_id,
                response_time=response_time
            )
            session.add(rt)
            session.commit()
    
    def add_log(self, monitor_id: int, level: str, message: str, details: dict = None):
        with self.session_factory() as session:
            log = Log(
                monitor_id=monitor_id,
                level=level,
                message=message,
                details=details
            )
            session.add(log)
            session.commit()
    
    def get_monitor_history(self, monitor_id: int, start_time: datetime = None, end_time: datetime = None, limit: int = 100):
        """Get historical data for a monitor with pagination and time range filtering."""
        with self.session_factory() as session:
            query = session.query(Monitor).filter(Monitor.id == monitor_id).first()
            
            if not query:
                return None
            
            # Build base queries with time range filters if provided
            check_query = session.query(Check).filter(Check.monitor_id == monitor_id)
            rt_query = session.query(ResponseTime).filter(ResponseTime.monitor_id == monitor_id)
            log_query = session.query(Log).filter(Log.monitor_id == monitor_id)
            
            if start_time:
                check_query = check_query.filter(Check.created_at >= start_time)
                rt_query = rt_query.filter(ResponseTime.created_at >= start_time)
                log_query = log_query.filter(Log.created_at >= start_time)
                
            if end_time:
                check_query = check_query.filter(Check.created_at <= end_time)
                rt_query = rt_query.filter(ResponseTime.created_at <= end_time)
                log_query = log_query.filter(Log.created_at <= end_time)
            
            # Apply ordering and limit
            check_query = check_query.order_by(Check.created_at.desc()).limit(limit)
            rt_query = rt_query.order_by(ResponseTime.created_at.desc()).limit(limit)
            log_query = log_query.order_by(Log.created_at.desc()).limit(limit)
            
            return {
                'monitor': {
                    'id': query.id,
                    'name': query.name,
                    'group': query.group,
                    'url': query.url,
                    'config': query.config
                },
                'response_times': [
                    {
                        'timestamp': rt.created_at.isoformat(),
                        'value': rt.response_time
                    }
                    for rt in rt_query.all()
                ],
                'checks': [
                    {
                        'timestamp': check.created_at.isoformat(),
                        'type': check.check_type,
                        'success': check.success,
                        'message': check.message,
                        'details': check.details
                    }
                    for check in check_query.all()
                ],
                'logs': [
                    {
                        'timestamp': log.created_at.isoformat(),
                        'level': log.level,
                        'message': log.message,
                        'details': log.details
                    }
                    for log in log_query.all()
                ]
            }

    def get_logs(self, page: int = 1, per_page: int = 100):
        """Get paginated logs ordered by newest first."""
        with self.session_factory() as session:
            # Get total count for pagination
            total_count = session.query(Log).count()
            
            # Calculate offset
            offset = (page - 1) * per_page
            
            # Get logs with monitor info
            logs = session.query(Log, Monitor.name.label('monitor_name'))\
                .join(Monitor)\
                .order_by(Log.created_at.desc())\
                .offset(offset)\
                .limit(per_page)\
                .all()
            
            # Calculate pagination info
            total_pages = (total_count + per_page - 1) // per_page
            has_next = page < total_pages
            has_prev = page > 1
            
            return {
                'logs': logs,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_prev': has_prev,
                'total_count': total_count
            }

# Create global database manager instance
Session = init_db()
db_manager = DatabaseManager(Session)
