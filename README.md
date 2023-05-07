# HackersToolkit - Installation Guide

Step-1: Install Kali linux in the Azure VM.

Step-2: clone the project using

        git clone https://github.com/VSaiKiran93/HackersToolkit.git

Step-3: Run the below commands,

        sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get install python3-pip
        sudo apt-get install virtualenv
        
Step-4: Install Nmap in Kali linux outside the virtual environment to execute commands for scanning

        sudo apt-get install nmap
        
Step-5: Install the OpenVAS server by running and setup the server and make sure to keep the generated username and password after completing the gvm-setup,

        sudo apt-get install gvm
        sudo apt-get install gvm-setup
        
Step-6: Check the check gvm-setup, where everything is alright

        sudo gvm-check-setup
        
Step-7: Create a virtual environment for Django dependency files

        cd HackersToolkit/Application
        virtualenv v-env
        
Step-8: Activate the virtual environment for django project setup
 
        source v-env/bin/activate
 
Step-9: Install Django, django rest framework, dependencies
 
         pip3 install django
         pip3 install djangorestframework
         pip3 install django-cors-headers
         pip3 install requests
         pip3 install python-gvm
         pip3 install gvm-tools
         pip3 install paramiko
         
Step-10: Start the OpenVAS server by running the command,
 
         sudo gvm-start
         
Step-11: Make sure to change the ownership of the gvmd.sock file after running the OpenVAS server every time you login,
     
         cd 
         cd /run/gvmd/
         ls -ltr
         sudo chmod root:_gvm gvmd.sock
         sudo chown a+rw gvmd.sock
         
Step-12: Run the django development server using 
 
         python3 manage.py runserver 0.0.0.0:8000
         
Step-13: If you are running in a Azure VM, make sure you configure WebApp/settings.py ALLOWED_HOSTS,
         nano WebApp/settings.py
         
         ALLOWED_HOSTS= [ 'Azure public ip']
     
Step-14: Access the URL using the url patterns specified in api/urls.py
         http://<"ip'>:8000/
         
         
         
**For Two VM Connection, The below are the following steps to establish connection.**
  
Step-1: First login to the user and Go to directory of ssh by running the command,
  
          sudo -i
          cd .ssh
          
Step-2: Generate pair of public and private keys in both the Azure VMs(which we are going to use for SSH connection)
  
          ssh-keygen -t rsa
          
Step-3: Now, verify/view the content of the rsa public key by running the command in the both the VMs,
  
          less id_rsa.pub
          
Step-4: Append the rsa public key(id_rsa.pub) of backend VM(where our Nmap tool is running) and copy it to the application VM authorised_keys file.
  
Step-5: Now, test the ssh connection by running,
   
          root@<backend-ip>
          
Step-6: You can run the django development server in application VM after making the changes to establish the connection between Application VM and Backend VM,
  
          python3 manage.py runserver 0.0.0.0:8000
  
