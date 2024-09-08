# Brain Battles Backend

## Overview

**Brain Battles** is an interactive quiz application that allows users to engage in various quizzes, track their progress, and challenge themselves. This repository contains the backend implementation of the Brain Battles platform, designed to handle user management, quiz creation, and scoring functionalities.

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
- **marshmallow**: For form validation and handling.
- **Flask-Migrate**: For database migrations and version control.
- **JWT**: JSON Web Token for secure user authentication and authorization.
- **Redis** (Optional): Used for caching tokens and managing session data.

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- Virtualenv (recommended for environment management)
- Redis (optional, for token caching)

### Installation Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/brain-battles-backend.git
   cd brain-battles-backend
