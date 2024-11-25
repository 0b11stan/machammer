pub fn print_buffer(buffer: &[u8]) {
    let mut i = 0;
    for o in buffer {
        print!("{:02x} ", o);
        i += 1;

        if i == 8 {
            print!(" ");
        } else if i == 16 {
            print!("\n");
            i = 0;
        }
    }
    print!("\n");
}

fn print_dhcp_option(option: &DHCPOption) {
    print!(
        "DHCPOption {{ opcode: {}, length: {}, payload:",
        option.opcode, option.length
    );
    for p in &option.payload {
        print!(" {}", p)
    }
    println!(" }}");
}
