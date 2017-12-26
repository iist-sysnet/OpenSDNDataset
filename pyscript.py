import subprocess
import time
import shlex
import os
import errno
import sys

# Forward the output to a null buffer, prevent output on screen
DEVNULL = open(os.devnull, 'wb')
#DEVNULL = sys.stdout
# Command to start the controller - %s is the name of the file
cmd_controller1 = "ryu-manager Controllers/%s --ofp-tcp-listen-port 6634"# --observe-links"
cmd_controller2 = "ryu-manager Controllers/%s --ofp-tcp-listen-port 6636"# --observe-links"
# Command to start the controller - %s is the name of the file
cmd_controller = "ryu-manager Controllers/%s --ofp-tcp-listen-port 6634 --observe-links"

# COmmand to start the tcpdump
cmd_tcpdump = "tcpdump -i any tcp src port 6634 or tcp src port 6636 or tcp dst port 6634 or tcp dst port 6636 -w %s"

#cmd_tcpdump = 'tshark -i any -f "port 6634 or port 6636" -w %s'

# For a 1000 iterations
for i in range(150):

    # Print current status
    print "\nRunning %d of total %d iterations\n" % (i+1, 3000)

    try:

        # Create intermediate folders if not present
        host_path = '/home/mininet/Data/RUN%05d/file.txt' % (i+1)
        filename = host_path
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        path = os.path.dirname(filename)

        # Gracefully close all the previous instances of mininet
        print "Clearing previous instances of mininet..."
        clear = subprocess.Popen(shlex.split("sudo mn -c"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Wait till the command is done executing
        clear.wait()

        # Log the data using tcp dump
        print "Start data logging at %s"%(cmd_tcpdump % ("%s/data1.pcap" % path))
        proc_dump = subprocess.Popen(shlex.split(cmd_tcpdump % ("%s/data1.pcap" % path)), shell=False,stdout=DEVNULL, stderr=subprocess.STDOUT)

        
        # Start mininet
        print "Starting Mininet..."


        
  
     
        proc_mini = subprocess.Popen(["python", "mininet_1.py", path, str(i+1)], shell=False)
        time.sleep(2)   
        
        print "Start the Controller code and wait..."

        # Start the compromised controller 1
        if((i+1)%6 == 0):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)
            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Start good controller
        elif((i+1)%6 == 1):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Start compromised controller 2
        elif((i+1)%6 == 2):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "bad_controller_01.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)
            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "bad_controller_01.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Start good controller
        elif((i+1)%6 == 3):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Start the good controller
        elif((i+1)%6 == 4):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)
            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "bad_controller_01.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

        # Start good controller
        elif((i+1)%6 == 5):
            proc_cont1 = subprocess.Popen(shlex.split(cmd_controller1 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)

            proc_cont2 = subprocess.Popen(shlex.split(cmd_controller2 % "good_controller.py"), shell=False, stdout=DEVNULL, stderr=subprocess.STDOUT)


        time.sleep(5)
        
        t = 0
        time_out = 50
        while t < time_out and proc_mini.poll() is None:
            time.sleep(1)  # (comment 1)
            t += 1
        #proc_mini.wait()

        if(proc_mini.poll() is None):

            print "Timeout, terminating mininet!"

    # CLose all the processes corresponding to this iteration.
    finally:

        try:
            print "Killing ", proc_mini.pid, " Mininet"
            proc_mini.kill()
        except:
            pass

        try:
            print "Killing ", proc_cont1.pid, " Controller"
            proc_cont1.kill()
        except:
            pass

        try:
            print "Killing ", proc_cont1.pid, " Controller"
            proc_cont2.kill()
        except:
            pass

        try:
            print "Killing ", proc_dump.pid, " TCPdump"
            proc_dump.kill()
        except:
            pass

        try:
            os.system("sudo killall -9 iperf -v")
        except:
            pass

        try:
            os.system("sudo killall -9 ITGRecv -v")
        except:
            pass

        try:
            os.system("sudo killall -9 tcpdump -v")
        except:
            pass

        try:
            os.system("sudo killall -9 ruby -v")
        except:
            pass

        try:
            os.system("sudo killall -9 ryu-manager -v")
        except:
            pass

        try:
            os.system("sudo killall -9 tshark -v")
        except:
            pass
