# ja4t-nginx-module
NGINX module to calculate and log JA4T fingerprints for TCP/TLS connections, including TCP RTT and TLS RTT, with configurable signature blocking and detailed connection metrics logging.

I'll guide you through compiling and installing this NGINX module. Here's a step-by-step process:

### Step 1: Set up the development environment

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y build-essential libpcre3-dev zlib1g-dev libssl-dev libyaml-dev

# Create a working directory
git clone https://github.com/Kedrics/ja4t-nginx-module.git
```

### Step 2: Download NGINX source code

```bash
# Get the latest stable NGINX version
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
```


### Step 3: Compile NGINX with the module

```bash
cd ~/nginx-ja4t-build/nginx-1.24.0

# Configure with the module
./configure \
  --prefix=/usr/local/nginx \
  --with-compat \
  --with-http_ssl_module \
  --add-dynamic-module=../ja4t-nginx-module

# Compile
make
sudo make install
```

### Step 4: Set up configuration files

Create the JA4T signatures file:

```bash
sudo mkdir -p /etc/nginx
sudo nano /etc/nginx/ja4t_signatures.yaml

Paste the following:
# ja4t_signatures.yaml
# List of JA4T hashes to block
- 7c3b2d8e  # Example Windows 10 Chrome
- a4f9c012  # Example Linux Firefox
- 5e2b9d4a  # Example MacOS Safari
```

Create the NGINX configuration:

```bash
sudo nano /usr/local/nginx/conf/nginx.conf

```
Paste the following:
```conf

#user  nobody;
worker_processes  1;
load_module modules/ngx_http_ja4t_module.so;
error_log  logs/error.log debug;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;
    ja4t_enabled on;
    
    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;
    # Load the JA4T module
    #load_module modules/ngx_http_ja4t_module.so;
    
    # Global JA4T settings
    ja4t_log_path /var/log/nginx/ja4t.log;
    ja4t_config_file /etc/nginx/ja4t_signatures.yaml;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;
	ja4t_enabled on;
        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
        
        location /static/ {
            
            alias /var/www/static/;
        }
        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    server {
        listen       443 ssl;
        server_name  localhost;

        ssl_certificate      server.crt;
        ssl_certificate_key  server.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }

}
```

# Create log directory and log
```bash
sudo mkdir -p /var/log/nginx
sudo touch /var/log/nginx/ja4t.log
```

### Step 6: Test and run NGINX

Test the configuration:

```bash
sudo /usr/local/nginx/sbin/nginx -t
```

Start NGINX:

```bash
sudo /usr/local/nginx/sbin/nginx
```

### Step 7: Verify it's working

Check if the module is loaded:

```bash
sudo lsof -p $(cat /usr/local/nginx/logs/nginx.pid) | grep ja4t
```

Monitor the JA4T log file:

```bash
sudo tail -f /var/log/nginx/ja4t.log
```
