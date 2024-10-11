

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import psutil
import json
import threading
import time
from collections import Counter
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///process_manager.db'  # Using SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class ProcessActivity(db.Model):
    __tablename__ = 'process_activity'
    id = db.Column(db.Integer, primary_key=True)
    process_name = db.Column(db.String(255), nullable=True)
    pid = db.Column(db.Integer, nullable=True)  # PID of the process
    status = db.Column(db.String(50), nullable=False)  # Active, Blocked, Unblocked
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_current = db.Column(db.Boolean, default=True)  # To track current status


class BlockedProcess(db.Model):
    __tablename__ = 'blocked_processes'
    id = db.Column(db.Integer, primary_key=True)
    process_name = db.Column(db.String(255), nullable=True)
    pid = db.Column(db.Integer, nullable=True)


@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/processes')
def processes():
    processes_dict = {}
    active_process_names = set()

    for proc in psutil.process_iter(['pid', 'name']):
        proc_info = proc.info
        process_name = proc_info.get('name')
        if not process_name:
            continue
        active_process_names.add(process_name)

        if process_name in processes_dict:
            processes_dict[process_name]['pids'].append(proc_info['pid'])
        else:
            processes_dict[process_name] = {
                'name': process_name,
                'pids': [proc_info['pid']]
            }
            existing_activity = ProcessActivity.query.filter_by(
                process_name=process_name, pid=proc_info['pid'], is_current=True).first()
            if not existing_activity:
                new_activity = ProcessActivity(
                    process_name=process_name,
                    pid=proc_info['pid'],
                    status='Active',
                    is_current=True
                )
                db.session.add(new_activity)
                db.session.commit()

    all_processes = ProcessActivity.query.all()

    process_activities = {}
    for activity in all_processes:
        if activity.process_name not in process_activities:
            process_activities[activity.process_name] = []
        process_activities[activity.process_name].append(activity)

    return render_template(
        'processes.html',
        processes=processes_dict.values(),
        activities=process_activities,
        active_names=active_process_names
    )


@app.route('/block/<string:process_name>')
def block_process(process_name):
    existing_block = BlockedProcess.query.filter_by(process_name=process_name).first()
    if not existing_block:
        blocked = BlockedProcess(process_name=process_name)
        db.session.add(blocked)
        db.session.commit()
        flash(f'Process {process_name} has been added to the blacklist.')
    else:
        flash(f'Process {process_name} is already in the blacklist.')
    return redirect(url_for('processes'))


@app.route('/unblock', methods=['POST'])
def unblock_process():
    process_name = request.form.get('process_name', '')
    pid = request.form.get('pid', type=int)
    if process_name and pid:
        BlockedProcess.query.filter_by(process_name=process_name, pid=pid).delete()
    elif process_name:
        BlockedProcess.query.filter_by(process_name=process_name).delete()
    elif pid:
        BlockedProcess.query.filter_by(pid=pid).delete()
    db.session.commit()
    ProcessActivity.query.filter_by(process_name=process_name, pid=pid).update({'is_current': False})
    db.session.commit()
    new_activity = ProcessActivity(
        process_name=process_name,
        pid=pid,
        status='Unblocked',
        is_current=True
    )
    db.session.add(new_activity)
    db.session.commit()
    flash(f'Process {process_name or pid} has been unblocked.')
    return redirect(url_for('unblock_list'))


@app.route('/unblock_list')
def unblock_list():
    blocked_processes = BlockedProcess.query.all()
    return render_template('unblock.html', blocked_processes=blocked_processes)


@app.route('/history')
def history():
    all_processes = ProcessActivity.query.order_by(ProcessActivity.timestamp.desc()).all()
    return render_template('history.html', processes=all_processes)


@app.route('/rule_editor', methods=['GET', 'POST'])
def rule_editor():
    if request.method == 'POST':
        # Check if a file is uploaded
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected')
            return redirect(request.url)
        file = request.files['file']
        if file:
            try:
                data = json.load(file)
                blacklisted = data.get('blacklist', [])
                if not blacklisted:
                    flash('Blacklist is empty or missing')
                    return redirect(request.url)
                for item in blacklisted:
                    if isinstance(item, int):
                        if not BlockedProcess.query.filter_by(pid=item).first():
                            blocked = BlockedProcess(pid=item)
                            db.session.add(blocked)
                    else:
                        if not BlockedProcess.query.filter_by(process_name=item).first():
                            blocked = BlockedProcess(process_name=item)
                            db.session.add(blocked)
                db.session.commit()
                flash('Rules have been successfully applied')
                return redirect(url_for('processes'))
            except json.JSONDecodeError:
                flash('Error reading JSON file')
                return redirect(request.url)
    return render_template('rule_editor.html')


@app.route('/analytics')
def analytics():
    current_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'create_time']):
        try:
            proc_info = proc.info
            proc.cpu_percent(interval=None)
            current_processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(0.1)

    for proc in current_processes:
        try:
            p = psutil.Process(proc['pid'])
            proc['cpu_percent'] = p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc['cpu_percent'] = 0.0

    anomalies = []

    cpu_threshold = 1.0
    high_cpu_processes = [proc for proc in current_processes if proc['cpu_percent'] > cpu_threshold]
    if high_cpu_processes:
        anomalies.append({
            'title': 'Processes with High CPU Usage',
            'processes': high_cpu_processes,
            'type': 'process'
        })

    memory_threshold = 100 * 1024 * 1024
    high_memory_processes = [proc for proc in current_processes if proc['memory_info'].rss > memory_threshold]
    if high_memory_processes:
        anomalies.append({
            'title': 'Processes with High Memory Usage',
            'processes': high_memory_processes,
            'type': 'process'
        })

    time_threshold = datetime.now() - timedelta(minutes=30)
    long_running_processes = [proc for proc in current_processes if
                              datetime.fromtimestamp(proc['create_time']) < time_threshold]
    if long_running_processes:
        anomalies.append({
            'title': 'Long-running Processes',
            'processes': long_running_processes,
            'type': 'process'
        })

    recent_time_threshold = datetime.now() - timedelta(minutes=10)
    recent_activities = ProcessActivity.query.filter(ProcessActivity.timestamp >= recent_time_threshold).all()
    process_counts = Counter(activity.process_name for activity in recent_activities if activity.status == 'Active')

    frequent_processes = [{'name': name, 'count': count} for name, count in process_counts.items() if
                          count > 2]  #
    if frequent_processes:
        anomalies.append({
            'title': 'Frequently Started Processes',
            'processes': frequent_processes,
            'type': 'frequent'
        })

    known_processes = set(['System', 'svchost.exe', 'explorer.exe'])
    unknown_processes = [proc for proc in current_processes if proc['name'] not in known_processes]
    if unknown_processes:
        anomalies.append({
            'title': 'Unknown Processes',
            'processes': unknown_processes,
            'type': 'process'
        })

    process_count_now = len(current_processes)
    past_time_threshold = datetime.now() - timedelta(minutes=10)
    past_activities = ProcessActivity.query.filter(ProcessActivity.timestamp <= past_time_threshold).all()
    process_count_past = len(
        set((activity.process_name, activity.pid) for activity in past_activities if activity.status == 'Active'))

    if process_count_past > 0 and process_count_now > process_count_past * 1.5:  # If count increased by more than 50%
        anomalies.append({
            'title': 'Sudden Increase in Process Count',
            'details': f'Number of processes increased from {process_count_past} to {process_count_now}',
            'type': 'details'
        })

    blocked_process_count = BlockedProcess.query.count()
    anomalies.append({
        'title': 'Blocked Processes',
        'details': f'Number of blocked processes: {blocked_process_count}',
        'type': 'blocked_processes'
    })

    return render_template('analytics.html', anomalies=anomalies)


@app.route('/analytics/data')
def analytics_data():
    process_data = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            mem_info = proc.memory_info()
            mem_usage = mem_info.rss / (1024 * 1024)  
            process_data.append({
                'name': proc.info['name'],
                'pid': proc.info['pid'],
                'cpu_percent': cpu_percent,
                'memory_usage': mem_usage
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    process_data.sort(key=lambda x: x['cpu_percent'], reverse=True)

    return jsonify(process_data)



def monitor_processes():
    while True:
        with app.app_context():
            blocked_processes = BlockedProcess.query.all()
            blocked_names = [bp.process_name for bp in blocked_processes if bp.process_name]
            blocked_pids = [bp.pid for bp in blocked_processes if bp.pid]
            for proc in psutil.process_iter(['pid', 'name']):
                proc_info = proc.info
                proc_name = proc_info.get('name')
                proc_pid = proc_info.get('pid')
                if proc_name in blocked_names or proc_pid in blocked_pids:
                    existing_activity = ProcessActivity.query.filter_by(
                        process_name=proc_name, pid=proc_pid, is_current=True
                    ).first()
                    if not existing_activity or existing_activity.status != 'Blocked':
                        ProcessActivity.query.filter_by(
                            process_name=proc_name, pid=proc_pid
                        ).update({'is_current': False})
                        db.session.commit()
                        new_activity = ProcessActivity(
                            process_name=proc_name,
                            pid=proc_pid,
                            status='Blocked',
                            is_current=True
                        )
                        db.session.add(new_activity)
                        db.session.commit()
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        time.sleep(1)


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    monitor_thread = threading.Thread(target=monitor_processes)
    monitor_thread.daemon = True
    app.run(debug=True)
