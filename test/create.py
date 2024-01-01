def create_test_file(file_name, size_GB):
    # Size in bytes
    size = size_GB * 1024 * 1024 * 1024

    # Create a file with the given name and size
    with open(file_name, 'wb') as file:
        file.seek(size - 1)
        file.write(b'\0')

if __name__ == '__main__':
    # Example usage:
    create_test_file('../data/12589/1GB_test_file.bin', 1)
