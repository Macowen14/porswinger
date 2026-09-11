# # vuln_test.py
# import subprocess

# user_input = input("Enter store ID: ")
# command = "echo Checking store " + user_input   # <-- the vulnerable concatenation
# subprocess.run(command, shell=True)# <-- shell=True is what makes injection possible


### test case 2 
# import subprocess

# user_input = input("Enter store ID: ")
# command = "echo Checking store " + user_input
# subprocess.run(command, shell=True, stdout=subprocess.DEVNULL)  # output hidden despite the command being executed


## test case 3
# fixed.py
# import subprocess

# user_input = input("Enter store ID: ")
# subprocess.run(["echo", "Checking store", user_input], shell=False)  # array form, no shell parsing


