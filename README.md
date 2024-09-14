# Brain Battles Backend

## Overview

**Brain Battles** is an interactive platform where users can create, participate in, and track quizzes on various topics. It allows users to sign up, login, logout and access a range of quizzes, each containing multiple-choice questions. Users can answer questions, receive immediate feedback on their responses, and see their scores and performance analytics. The platform also supports updating user profiles and managing quizzes through a simple interface, ensuring a seamless experience from quiz creation to taking and reviewing quizzes..

The backend is built using Flask, a lightweight Python web framework, with SQLAlchemy for ORM-based database interactions. It features robust authentication using JWT (JSON Web Tokens) and offers email notifications for user activities.

## Features

- **User Authentication and Authorization**: Secure sign-up, login, and authentication processes using JWT. Includes functionality for OTP verification and token refresh.
- **Quiz Management**: Create and manage quizzes, including adding and organizing questions and answers.
- **Scoring System**: Track and manage user scores and progress in quizzes.
- **Email Notifications**: Send email notifications for important user actions such as sign-ups and password resets.
- **Role-Based Access**: Handle different user roles and permissions (e.g., admin and normal users).

## Technologies Used

- **Flask**: A micro web framework used for building the RESTful API.
- **SQLAlchemy**: ORM library for database interactions and management.
- **Flask-Mail**: Extension for handling email functionality.
- **marshmallow**: For validation and handling.
- **Flask-Migrate**: For database migrations and version control.
- **JWT**: JSON Web Token for secure user authentication and authorization.
- **Redis**: Used for caching tokens and managing session data.
- **Docker**: Containerization platform used for packaging the application and its dependencies into a container.

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- Virtualenv (recommended for environment management)
- Redis (optional, for token caching)

### Installation Steps

1. **Clone the Repository**

   ```bash
   https://github.com/abdelrhman892/Brain-Battles.git
   cd Brain-Battless
