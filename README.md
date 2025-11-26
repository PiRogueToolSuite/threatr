<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>Threatr</h1>
<p>
Threat intelligence meta search engine.
</p>
<p>
License: GPLv3
</p>
<p>
<a href="https://pts-project.org">Website</a> | 
<a href="https://pts-project.org/docs/colander/overview/">Documentation</a> | 
<a href="https://discord.gg/qGX73GYNdp">Support</a>
</p>
</div>

## Local deployment
This section describes the procedure to host Threatr locally only. It's not supposed to
be exposed to the Internet directly.

### Requirement
Docker and Docker Compose must be installed on the machine hosting Threatr.

### Initial deployment
**1. Download the Docker Compose file and the `.env`**  
```bash
wget https://raw.githubusercontent.com/PiRogueToolSuite/threatr/refs/heads/main/deployment/.env
wget https://raw.githubusercontent.com/PiRogueToolSuite/threatr/refs/heads/main/deployment/threatr-local.yml
```
**2. Change the secrets**  
Edit the `.env` file and replace the values of `DJANGO_SECRET_KEY` and `POSTGRES_PASSWORD` with a new randomly generated secret.

**3. Start Threatr**  
```bash
docker compose -f threatr-local.yml up -d
```

**4. Create the admin user**  
```bash
docker compose -f threatr-local.yml run --rm threatr-local-front python manage.py createsuperuser --username admin
```

**5. Create a new user and their API key**  
* connect to the administration panel `http://127.0.0.1:9080/admin`
* go to **Users** menu
* create a new regular user
* go to **Tokens** menu
* generate a new API key for the created user

**6. Configure integrations**  
Refer to [the official documentation](https://pts-project.org/docs/threatr/integrations/).


### Update
```bash
docker compose -f threatr-local.yml pull
docker compose -f threatr-local.yml up -d
```

### Stop
```bash
docker compose -f threatr-local.yml stop
```

## REST API
Refer to [the official documentation](https://pts-project.org/docs/threatr/rest-api/).

_Example in Python_
```python
import requests

def send_request(data):
    """
    Send the request to Threatr. If Threatr returns a status code equals to 201,
    this means the client has to come back later.

    If the status code is equal to 200, we are ready to return the result to the client.

    The data sent to Threatr must follow this structure:
    {
        "super_type": the entity super type such as observable or device,
        "type": the entity type such as IPv4 or server,
        "value": the actual subject of the search such as 1.1.1.1,
        "force": indicated to update Threatr cache by querying all vendors
    }

    :param data: the data to be sent
    :return: the query results and a boolean telling if the client has to wait and come back later, False otherwise
    """
    headers = {'Authorization': f'Token API_KEY'}
    response = requests.post(
        'http://127.0.0.1:9080/api/request/', 
        headers=headers, 
        json=data
    )
    if response.status_code == 201:
        return [], True
    elif response.status_code == 200:
        return response.json(), False
    else:
        return [], False


data = {
    "super_type": "observable",
    "type": "domain",
    "value": "google.com",
    "force": False
}
d, come_back_later = send_request(data)
```
