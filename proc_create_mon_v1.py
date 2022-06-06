
#http://timgolden.me.uk/python/wmi/wmi.html

# scheint nicht alle Aktion mitzubekommen; threats und executions über cli werden nicht angezeigt!!!!
# nuitka --onefile proc_create_mon_v1.py
# learning mode? hash over filename and path?

import wmi, psutil, hashlib, logging, socket, time
from datetime import datetime

#speichert alle bekannten hashes
known_hashes = []




# Getting the current date and time
dt = datetime.now()


# logging
#setup logging basic configuration for logging to a file
logging.basicConfig(filename="edr.log", level=logging.DEBUG)



#syslog
syslog_server_ip = "127.0.0.1"
syslog_server_port = 514





class Syslog:
  """A syslog client that logs to a remote server.

  Example: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com -
  """



  def __init__(self, host="localhost", port=514):
    self.host = host
    self.port = port
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  def send(self, message):
    "Send a syslog message to remote host using UDP."
    tstr = time.strftime("%Y%m%d-%H%M%S")
    mhostname = socket.gethostname()
    string = message
    length = 1100
    for i in range(0, len(string), length):
        chunk = string[i:length+i]
        data = "<165>1 " + tstr + " " + mhostname + " - %s" % (chunk)
        try:
                self.socket.sendto(data.encode(), (self.host, self.port))
        except:
            print("Error sending to syslog!")


#slog = Syslog(host=syslog_server_ip, port=int(syslog_server_port))
slog = Syslog(host=syslog_server_ip, port=int(syslog_server_port))


def logEvent(message):
    #logging.warning('This is a WARNING message')
    #logging.error('This is an ERROR message')
    #logging.critical('This is a CRITICAL message')
    logging.info(str(dt) + ";" + str(message))
    slog.send(str(dt) + ";" + str(message))




def killProcess(process_created):
    try:
        process_created.Terminate()
    except:
        pass


def md5Checksum(filePath):
    try:
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
    except:
        return ""
    

def getProcName(pid):
    c = wmi.WMI ()

    for process in c.Win32_Process ():
        if process.ProcessId == pid:
            #print process.ProcessId, process.Name
            return process.Name
    return ""


def getProcNamePS(pid_id):
    try:
        process_pid = psutil.Process(pid_id)
        #print(process_pid)
        # Gives You PID ID, name and started date
        # psutil.Process(pid=1216, name='ATKOSD2.exe', started='21:38:05')

        # Name of the process
        process_name = process_pid.name()
        return process_name
    except:
        return ""
    
    
def getProcInfos(pid):
    for proc in psutil.process_iter():
        proc_info = dict()
        proc_info["pid"] = ""
        proc_info["ppid"] = ""
        proc_info["name"] = ""
        proc_info["connections"] = ""
        proc_info["ppid_name"] = ""
        
        with proc.oneshot():
            
            if proc.pid == pid:
                #print("PPID NAME: " + str(proc.name()))          
                proc_info["pid"] = str(proc.pid)
                proc_info["ppid"] = str(proc.ppid())
                proc_info["name"] = str(proc.name())
                proc_info["connections"] = str(proc.connections())
                proc_info["ppid_name"] = str(proc.name())
                return proc_info
            
        return proc_info
                

        
logEvent('EDR STARTED')

slog.send("hello syslog")



# process creation
c = wmi.WMI ()

watcher = c.watch_for (
  notification_type="Creation",
  wmi_class="Win32_Process",
  delay_secs=2,
)

while 1:
  process_created = watcher() 

  md5_hash = md5Checksum(process_created.ExecutablePath)
  # proc_info = getProcInfos(process_created.ParentProcessId)

  print("----------------------------------------------------")
  print("NAME: " + str(process_created.Name))
  print("Description: " + str(process_created.Description))
  print("CSNAME: " + str(process_created.CSName))
  print("OSNAME: " + str(process_created.OSName))
  print("PID: " + str(process_created.ProcessId))
  print("PPID: " + str(process_created.ParentProcessId))
  print("PPIDNAME: " + str(getProcNamePS(process_created.ParentProcessId)))
  print("PATH: " + str(process_created.ExecutablePath))
  print("HASH: " + str(md5_hash))
  #print("CONNECTIONS: " + str(proc_info["connections"]))
    
  process_info = str(process_created.Name) + ";" + str(process_created.Description) + ";" + str(process_created.CSName) + ";" + str(process_created.OSName) + ";" + str(process_created.ProcessId) + ";" + str(process_created.ParentProcessId) + ";" + str(getProcNamePS(process_created.ParentProcessId)) + ";" + str(process_created.ExecutablePath) + ";" + str(md5_hash)
    
  logEvent("PROCESS CREATED: " + process_info)
    
  # insert hash to db
  if str(md5_hash) not in known_hashes:
        known_hashes.append(md5_hash)
        logEvent(process_info)
        print("ADD NEW HASH TO HASH-TABLE: " + process_info)


  # insert logic for anomali check, connections and yara scan 
  # run yara over process-info output
  # $str1 = "word.exe $str2 = "cmd.exe" etc. dann kill process

  # blacklisting processes
  #not_allowed_processes = ["calculator.exe", "cmd.exe", "powershell.exe", "vssadmin.exe"]
  not_allowed_processes = ["vssadmin.exe"]
    
  if str(process_created.Name).lower() in not_allowed_processes:
        logEvent("NOT ALLOWED PROCESS DETECTED (KILL): " + process_info)
        killProcess(process_created)








# get hash md5, sha256
# syslog
# yara-scan?
# network infos -> pstools
# 