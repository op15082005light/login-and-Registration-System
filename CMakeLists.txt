cmake_minimum_required(VERSION 3.10)
project(LoginSystem LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(login_system
    src/main.cpp
    src/Hasher.cpp
    src/User.cpp
    src/UserDatabase.cpp
    src/InputValidator.cpp
    src/Auth.cpp
    src/Dashboard.cpp
)
