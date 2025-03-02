<a id="readme-top"></a>

<br />
<div align="center">

<h1 align="center">Flask Dockerized Web Application</h3>

  <p align="center">
    A secure, containerized Flask web messaging/posting application with Nginx as a reverse proxy.
    <br />
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project

![Image](https://github.com/user-attachments/assets/a12546cd-ee07-414a-a1bc-bfc98dc15d4e)

This project is a Flask-based messaging application containerized with Docker and secured with Nginx as a reverse proxy. It includes user authentication, two-factor authentication (TOTP), password recovery, and PostgreSQL database support. The application follows security best practices, ensuring input validation, data sanitization, and logging for login attempts.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

- ![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask) [Flask](https://flask.palletsprojects.com/en/stable/)
- ![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white) [Docker](https://www.docker.com/)
- ![Nginx](https://img.shields.io/badge/Nginx-269539?style=flat&logo=nginx&logoColor=white) [Nginx](https://nginx.org/)
- ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=flat&logo=postgresql&logoColor=white) [PostgreSQL](https://www.postgresql.org/)


<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

Follow the instructions below to set up and run the project locally.

### Prerequisites

Ensure you have the following installed:

- Docker
- Nginx
- Python 3.10+

### Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/github_username/repo_name.git
   cd repo_name
   ```
2. Create and configure the `.env` file:
   ```sh
   cp .env.example .env
   ```
   Modify the `.env` file with the appropriate database credentials and secret keys.
3. Build and start the containers:
   ```sh
   docker-compose up --build
   ```
4. Generate self-signed SSL certificates with:
   ```bash
   mkdir -p ./certs
   openssl req -x509 -newkey rsa:4096 -keyout ./certs/key.pem -out ./certs/cert.pem -days 365 -nodes
   ```
5. Access the application at `https://localhost`

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

This project provides:
- Secure user authentication with password hashing
- Two-factor authentication using TOTP
- Secure password recovery process
- Posting messages with basic formatting
- Auto-signing and verifying message integrity (a little sign indicating whether the message has been tampered with)
- Restoring access to the account
- Viewing each user's profile with all their posts
- Monitoring login attempts (successfull or not, IP, user agent, timestamp)
- Thorough user input sanitization and validation

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

**Gmail** – [kravtsov2109@gmail.com](mailto:kravtsov2109@gmail.com)

**LinkedIn** – [Serhii Kravtsov](https://www.linkedin.com/in/serhii-kravtsov-/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

