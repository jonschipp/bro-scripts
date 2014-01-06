@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::read_files += {
        "test/cif.txt",
        "tests/cif2.txt",
};

