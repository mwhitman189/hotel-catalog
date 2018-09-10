# Hotel Catalog

This web application allows users to view, add, update, and delete hotels in Yamagata, Japan. Anyone can view the basic hotel information without signing in. Users must sign in in order to add, edit, or delete hotels, and to view JSON data.

Udacity Reviewer: The 'client_secrets.json' file has been sent via zip.


## Getting Started

The following sections will guide you through setting up and running a copy of the project on your local machine.


### Prerequisites

In order to get started, you need the following installed on your machine:
- Python 2.7
- Flask SeaSurf
- Jinja2

These can all be installed through the Udacity Vagrant VM installation:
- Redis (redis)
- Flask (flask)
- Flask HTTP Auth (flask-httpauth)
- SQLAlchemy (sqlalchemy)
- OAuth2 Client (oauth2client)
- Passlib (passlib)
- pip2 (`$ sudo apt-get install python-pip` for linux)


### Installation

Cloning the Virtual Machine is a quick way to get all of the remaining necessary depenecies.

Otherwise, you'll have to install each one independently, following the same procedures are in the SeaSurf and Jinja2 installations--the installation names are in parentheses.

If any of these do not install properly, try a 'sudo' install.


##### Flask Seasurf installation:

`$ pip install flask-seasurf`


##### Jinja2 installation:

`$ pip install jinja2`


##### Udacity VM installation:

`$ git clone https://github.com/udacity/fullstack-nanodegree-vm.git`


### OAuth2 client ID:

You will need to create a new Google developer project and get a new 'client_secrets.json' file, then copy it into the root directory of the project.


### Running the program:

Run the program using python2.7 in a virtual environment:
1. `cd` into the 'hotels' folder from the terminal.
2. Type `vagrant up` to start the VM. (It may take a minute or two to start.)
3. Type `vagrant ssh` to signin to the VM.
4. `cd` back into the 'hotels' folder from the VM.
5. type `python HotelsProject.py`

Now you can access the site on 'http://localhost:8000/'


## Built With

- Flask - Web framework
- SeaSurf - CSRF token management
- Redis - Rate limiting


## Authors

- Miles Whitman - *initial contributor*
