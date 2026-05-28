cmake_minimum_required(VERSION 3.20)

project(kernel_pocs LANGUAGES CXX)

add_subdirectory(process_handle_callbacks/client)
add_subdirectory(process_image_thread_monitor/client)
add_subdirectory(driver_inventory/client)
add_subdirectory(communication_surface/client)
