cmake_minimum_required(VERSION 3.10)
project(LoginSystem LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

# Core application
add_executable(login_system
    src/main.cpp
    src/Hasher.cpp
    src/User.cpp
    src/UserDatabase.cpp
    src/InputValidator.cpp
    src/Auth.cpp
    src/Dashboard.cpp
)

# Test targets
add_executable(test_runner
    tests/test_suite.cpp
    src/Hasher.cpp
    src/User.cpp
    src/UserDatabase.cpp
    src/InputValidator.cpp
    src/Auth.cpp
    src/Dashboard.cpp
)

add_executable(test_edge_cases
    tests/test_edge_cases.cpp
    src/Hasher.cpp
    src/User.cpp
    src/UserDatabase.cpp
    src/InputValidator.cpp
    src/Auth.cpp
    src/Dashboard.cpp
)
