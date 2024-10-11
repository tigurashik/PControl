import time
import psutil
from datetime import datetime
from collections import Counter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import ProcessActivity, BlockedProcess  # Замените на фактический путь
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine = create_engine('sqlite:///process_manager.db')
Session = sessionmaker(bind=engine)
session = Session()

def monitor_processes():
    while True:
        blocked_processes = session.query(BlockedProcess).all()
        blocked_names = [bp.process_name for bp in blocked_processes if bp.process_name]
        blocked_pids = [bp.pid for bp in blocked_processes if bp.pid]
        for proc in psutil.process_iter(['pid', 'name']):
            proc_info = proc.info
            proc_name = proc_info.get('name')
            proc_pid = proc_info.get('pid')
            if proc_name in blocked_names or proc_pid in blocked_pids:
                existing_activity = session.query(ProcessActivity).filter_by(
                    process_name=proc_name, pid=proc_pid, is_current=True
                ).first()
                if not existing_activity or existing_activity.status != 'Blocked':
                    session.query(ProcessActivity).filter_by(
                        process_name=proc_name, pid=proc_pid
                    ).update({'is_current': False})
                    session.commit()
                    new_activity = ProcessActivity(
                        process_name=proc_name,
                        pid=proc_pid,
                        status='Blocked',
                        timestamp=datetime.now(),
                        is_current=True
                    )
                    session.add(new_activity)
                    session.commit()
                try:
                    proc.kill()
                    logger.info(f"Заблокирован процесс {proc_name} с PID {proc_pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.error(f"Не удалось заблокировать процесс {proc_name} с PID {proc_pid}: {e}")
        time.sleep(5) 

if __name__ == '__main__':
    ProcessActivity.__table__.create(bind=engine, checkfirst=True)
    BlockedProcess.__table__.create(bind=engine, checkfirst=True)
    monitor_processes()
