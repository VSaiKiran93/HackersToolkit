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
        
Step-5: Create a virtual environment for Django dependency files

        virtualenv v-env
        
 Step-6: Activate the virtual environment for django project setup
 
        source v-env/bin/activate
 
 Step-7: Install Django and django rest framework
 
         pip install django
         pip install djangorestframework
         pip install djangocors-headers
         
 Step-8: Run the django development server using 
 
         python3 manage.py runserver 0.0.0.0:8000
         
 Step-9: If you are running in a Azure VM, make sure you configure WebApp/settings.py ALLOWED_HOSTS,
         nano WebApp/settings.py
         ALLOWED_HOSTS= [ 'Azure public ip']
     
 Step-10: Access the URL using the url patterns specified in api/urls.py
         http://<"ip'>:8000/
