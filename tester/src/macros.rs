
#[macro_export]
macro_rules! test_parser {
    ($func_name:ident, $file:literal, $function:expr) => {
        #[test]
        fn $func_name() {
            let test_file = fixture_dir().unwrap().join($file);

            let mut buffer = String::new();
            read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

            for (test_name, value) in buffer.parse::<Table>().unwrap() {
                println!("Run {}", test_name);

                let test: TestSuitStr = value.try_into().unwrap();
                let (remaining, result) = $function(&test.input).unwrap();

                assert_eq!(remaining, test.remaining);
                assert_eq!(&test.expected, result);
            }
        }
    };
}

#[macro_export]
macro_rules! test_parser_struct {
    ($func_name:ident, $file:literal, $function:expr) => {
        #[test]
        fn $func_name() {
            let test_file = fixture_dir().unwrap().join($file);

            let mut buffer = String::new();
            read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

            for (test_name, value) in buffer.parse::<Table>().unwrap() {
                println!("Run {}", test_name);

                let test: TestSuit = value.try_into().unwrap();
                let (remaining, result) = $function(&test.input).unwrap();

                assert_eq!(remaining, test.remaining);
                assert_eq!(
                    toml::to_string(&test.expected).unwrap(),
                    toml::to_string(&result).unwrap()
                );
            }
        }
    };
}

#[macro_export]
macro_rules! test_parser_vec {
    ($func_name:ident, $file:literal, $function:expr) => {
        #[test]
        fn $func_name() {
            let test_file = fixture_dir().unwrap().join($file);

            let mut buffer = String::new();
            read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

            for (test_name, value) in buffer.parse::<Table>().unwrap() {
                println!("Run {}", test_name);

                let test: TestSuit = value.try_into().unwrap();
                let (remaining, results) = $function(&test.input).unwrap();
                assert_eq!(remaining, test.remaining);

                let mut index = 0;
                for inner in test.expected.as_array().unwrap() {
                    println!("Run {}", index);
                    assert_eq!(
                        toml::to_string(&inner).unwrap(),
                        toml::to_string(&results[index]).unwrap()
                    );
                    index += 1
                }
            }
        }
    };
}
