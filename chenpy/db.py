import rocksdbpy


def db_options():
    opts = rocksdbpy.Option()
    opts.create_if_missing(True)
    opts.set_max_open_files(10)
    opts.set_use_fsync(True)
    opts.set_bytes_per_sync(1024 * 1024)
    opts.optimize_for_point_lookup(1024 * 1024)
    opts.set_bloom_locality(16)
    return opts


def get(path):
    return rocksdbpy.open(path, db_options())
