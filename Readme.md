## JWTInAspNetCore

This project is web API for authentication and authorization using JWT (Json Web Token) and Refresh Token concepts, built with Asp.Net Core.

## Table of contents
- [Features](#features)
- [Technologies](#technologies)
- [Setup](#setup)
- [Usage](#usage)
- [Api Endpoints](#api-endpoints)

## Features

- User registration and login
- JWT token generation and validation
- Refresh token generation and management
- Secure endpoints with token authentication
- logout functionality

## Technologies

- Asp.Net Core
- EntityFrameworkCore
- SQL Server
- JWT

## Setup

1. Clone the repository

```sh
git clone https://github.com/Dip-Kishor/JWTInAspNetCore.git
```

2. Navigate to project directory

```sh
cd JWTInAspNetCore
```

3. Setup data

```sh
dotnet ef database update
```
>**Note**: Make sure to use your own sql server Username and Password in connection string.

4. Run the application

```sh
dotnet run
```
## Usage
1. Open your API client(such as postman) or web browser.
2. Use the registration endpoint to create new user.
3. Use the login endpoint to authenticate and receive JWT token.
4. Use JWT token to access secure endpoints.
5. Use the logout endpoint to invalidate the user and tokens.
> **Note:** The refresh token is used to validate the user and generate a new JWT (access) token when the previous one expires. This process is handled automatically using middleware.

## API Endpoints
- `POST /api/user/register` - Register a new user
- `POST /api/user/login` - Login and receive a JWT token
- `POST /api/user/logout` - Logout and invalidate the refresh token
- `GET /api/Test/TestAdmin` - Example of a secure endpoint that requires authentication of admin
- `GET /api/Test/TestManager` - Example of a secure endpoint that requires authentication of manager
- `GET /api/Test/TestUser` - Example of a secure endpoint that requires authentication of user
- `GET /api/Test/TestBoth` - Example of a secure endpoint that requires authentication of admin or manager
