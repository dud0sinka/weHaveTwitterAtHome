<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/github_username/repo_name">
  </a>

<h3 align="center">Flask Dockerized Web Application</h3>

  <p align="center">
    A secure, containerized Flask web messaging/posting application with Nginx as a reverse proxy.
    <br />
    <a href="https://github.com/github_username/repo_name"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/github_username/repo_name">View Demo</a>
    &middot;
    <a href="https://github.com/github_username/repo_name/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/github_username/repo_name/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

This project is a Flask-based messaging application containerized with Docker and secured with Nginx as a reverse proxy. It includes user authentication, two-factor authentication (TOTP), password recovery, and PostgreSQL database support. The application follows security best practices, ensuring input validation, data sanitization, and logging for login attempts.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![Flask][Flask]][Flask-url]
* [![Docker][Docker]][Docker-url]
* [![Nginx][Nginx]][Nginx-url]
* [![PostgreSQL][PostgreSQL]][PostgreSQL-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

Follow the instructions below to set up and run the project locally.

### Prerequisites

Ensure you have the following installed:

- Docker
- Docker Compose
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

Serhii - [@twitter_handle](https://twitter.com/twitter_handle) - email@example.com

LinkedIn - 

Project Link: [https://github.com/github_username/repo_name](https://github.com/github_username/repo_name)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

