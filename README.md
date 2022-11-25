# Stack

## Installation

After cloning from github, firstly you need to give Arkime's scripts permission in order to execute. 

```bash
  sudo chmod +x arkime -R
```
Next adjust ```.env``` file by specifing interface you want to listen on.
```bash
  vim .env
```    
As a final step just hit
```bash
  sudo docker-compose --env-file .env up -d
```
