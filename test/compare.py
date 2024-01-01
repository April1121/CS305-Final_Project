import hashlib


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


if __name__ == '__main__':
    # Adjust the paths relative to the 'test' directory
    data_file = '../data/12589/1GB_test_file.bin'
    download_file = '../download/1GB_test_file.bin'
    print(md5(data_file) == md5(download_file))
