use parser::rule;

fn main() {
    let arg = "-A INPUT -g MY_CHAIN --ctstate RELATED,ESTABLISHED";
    let res = rule(arg);

    match res {
        Ok(arg) => {
            let (input, res) = arg;
            println!("{}{:?}", input, res);
            println!("{}", toml::to_string(&res).unwrap())
        }

        Err(error) => panic!("Problem opening the file: {error:?}"),
    };
}
