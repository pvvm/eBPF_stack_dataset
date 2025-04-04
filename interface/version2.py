import streamlit as st
from google import genai
from google.genai import types
import time
import streamlit_mermaid as stmd
import re

st.title("eBPF Callstack Tracker")
st.subheader("Hello, I am an AI assistant whose objective is to simplify tracking the eBPF callstack\
    size across a program. Please write an eBPF program below")

def initialize_model():
    generate_content_config = types.GenerateContentConfig(
        temperature=1,
        top_p=0.95,
        top_k=40,
        max_output_tokens=8192,
        response_mime_type="text/plain",
        system_instruction=[
            types.Part.from_text(text="""You are a system that outputs the mermaid graph that represents an eBPF program.
    Each node represents the function and the variables declared in it, and the function calls are represented by arrows
    that connect the nodes. And for each variable, you show the size in bytes that the variable's type occupies.
    In case the function has two return statements, the first value of the node should be "return -> X", where X is the
    size of the value returned.
    You must add padding between variables in case the sum of previous variables isn't divisible by the variable's size,
    for example, if the current sum is 30 and the variable is 8 bytes long, you must add 2 of padding, represent this via:
    padding -> X, where X is the size of padding.
    Consider that all pointers occupy 8 bytes. At the end of each node you add the total amount of bytes that the node.
    You don't give explanations, you only show the result of the mermaid graph. No extra messages other than the mermaid graph.
    Do not use parentheses, square brackets, and brackets inside the nodes' values.
    THE WHOLE OUTPUT MUST BE IN A SINGLE LINE
    Now, I will show you 6 examples, showing the input and expected output of each:
    Example 1:
    Input: SEC("xdp") int xdp_prog(struct xdp_md *ctx) { return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> Total: 8 ]
    Example 2:
    Input: SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u32 variable = 100; variable += 51; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> variable -> 4 <br> Total: 12 ]
    Example 3:
    Input: SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u8 variable1 = 5; __u64 variable2; variable2 = 5 + variable1; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> variable1 -> 1 <br> Padding -> 7 <br> variable2 -> 8 <br> Total: 24 ]
    Example 4:
    Input: __u8 helper() { __u8 var = 123; if(var != 100) { __u32 value2 = 3; value2 *= 2; var = value2 - value2 + 1; } return var; } SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u32 this = 1; __u8 value = 0; __u64 val2 = value + 1; this += -1; if(this > value) { value = 5 + this; __u32 testing = 123; testing *= 123; if(this > 1000) { testing = 1; } helper(); } __u8 a = 20; a += this; a += val2; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> this -> 4 <br> value -> 1 <br> Padding -> 3 <br> val2 -> 8 <br> testing -> 4 <br> a -> 1 <br> Total: 29 ] --> B \n B[ <b> helper </b> <br> var -> 1 <br> Padding -> 3 <br> value2 -> 4 <br> Total: 8]
    Example 5:
    Input: struct testing { __u32 amem; __u64 example; }; struct str_testando { __u8 hello; __u64 trying_out; }; void testing_func(__u32 *value) { if(*value > 123) { *value = 10; } return; } __u16 helper() { __u8 g = 12; __u16 uga = g * 2; __u32 value; value = 500; testing_func(&value); if(value > uga) { return uga; } return value; } SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u32 this = 1; __u8 value = 0; __u8 you_are_cool = 1 + 5; this = this + -1; __u32 data_start = ctx->data; __u32 data_end = ctx->data_end; if(data_end < data_start) return XDP_DROP; struct xdp_md *copy = ctx; __u32 rx_index = copy->rx_queue_index; if(you_are_cool > value) { __u16 helper_return = helper(); helper_return = helper_return + 1;; return XDP_PASS; } if(rx_index != 0) this = 0; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> return -> 4 <br> Padding -> 4 <br> ctx -> 8 <br> this -> 4 <br> value -> 1 <br> you_are_cool -> 1 <br> Padding -> 2 <br> data_start -> 4 <br> data_end -> 4 <br> copy -> 8 <br> rx_index -> 4 <br> helper_return -> 2 <br> Total: 46 ] --> B \n B[ <b> helper </b> <br> g -> 1 <br> Padding -> 1 <br> uga -> 2 <br> Padding -> 2 <br> value -> 4 <br> return -> 2 <br> Total: 4] --> C \n C[ <b> testing_fun </b> <br> value -> 8 <br> Total: 8]
    Example 6:
    Input: // SPDX-License-Identifier: GPL-2.0 #include <linux/bpf.h> #include <bpf/bpf_helpers.h> struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, __u32); __uint(max_entries, 32); } xdp_map SEC(".maps"); struct value { __u32 testing; __u32 testing2; }; struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct value); __uint(max_entries, 32); } map_value SEC(".maps"); __u32 multiply_ten(__u32 number) { return number * 10; } SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u64 value = 1; __u8 value1 = 2; __u16 value2 = 3; __u8 value3 = 4; __u32 value4 = 5; __u64 total = value + value1 + value2 + value3 + value4; total = multiply_ten(total); return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD A[ <b> xdp_prog </b> <br> ctx -> 8 <br> value -> 8 <br> value1 -> 1 <br> Padding -> 1 <br> value2 -> 2 <br> value3 -> 1 <br> Padding -> 3 <br> value4 -> 4 <br> Padding -> 4 <br> total -> 8 <br> Total: 40 ] --> B B[ <b> multiply_ten </b> <br> number -> 4 <br> Total: 4]
    Example 7:
    Input: // SPDX-License-Identifier: GPL-2.0 #include <linux/bpf.h> #include <bpf/bpf_helpers.h> #include <bpf/bpf_endian.h> #include <linux/if_ether.h> struct hdr_cursor { void *pos; }; int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr) { struct ethhdr *eth = nh->pos; int hdrsize = sizeof(*eth); /* Byte-count bounds check; check if current pointer + size of header * is after data_end. */ if (nh->pos + 1 > data_end) return -1; nh->pos += hdrsize; *ethhdr = eth; return eth->h_proto; /* network-byte-order */ } SEC("xdp") int xdp_prog(struct xdp_md *ctx) { void *data_end = (void *)(long)ctx->data_end; void *data = (void *)(long)ctx->data; struct ethhdr *eth; /* Default action XDP_PASS, imply everything we couldn't parse, or that * we don't want to deal with, we just pass up the stack and let the * kernel deal with it. */ __u32 action = XDP_PASS; /* Default action */ /* These keep track of the next header type and iterator pointer */ struct hdr_cursor nh; int nh_type; /* Start next header cursor position at data start */ nh.pos = data; /* Packet parsing in steps: Get each header one at a time, aborting if * parsing fails. Each helper function does sanity checking (is the * header type in the packet correct?), and bounds checking. */ nh_type = parse_ethhdr(&nh, data_end, &eth); if (nh_type != bpf_htons(ETH_P_IPV6)) return XDP_DROP; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD A[ <b> xdp_prog </b> <br> ctx -> 8 <br> data_end -> 8 <br> data -> 8 <br> eth -> 8 <br> action -> 4 + 4 <br> nh -> 8 <br> nh_type -> 4 <br> return -> 4 <br> Total: 60 ] --> B B[ <b> parse_ethhdr </b> <br> return -> 4 <br> Padding -> 4 <br> nh -> 8 <br> data_end -> 8 <br> ethhdr -> 8 <br> eth -> 8 <br> hdrsize -> 4 <br> Total: 44]
    """),
        ],
    )
    return generate_content_config

    """int function(int a, long int b) {
    a = b;
    }
    int main() {
    int a = 5;
    long int b = 4;
    function(a, b);
    }
    The output should be:
    graph TD
    A[<b>main</b><br>a -> 4<br>b -> 8<br>Total: 12] --> B;
    B[<b>function</b><br>a -> 4<br>b -> 8<brTotal: 12>];"""

if __name__ == "__main__":
    generate_content_config = initialize_model()
    client = genai.Client(api_key=<insert_key_here>)

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # int function(int a, long int b) {a = b;} int main() { int a = 5; long int b = 4; function(a, b);}
    if prompt := st.chat_input("Enter the eBPF program"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        with st.chat_message("assistant"):
            response = client.models.generate_content(
                model = "gemini-2.0-flash",
                contents = prompt,
                config = generate_content_config,
            )
            start_index = response.text.find("graph TD")
            end_index = response.text.rfind("```")
            if(end_index != -1):
                mermaid_formula = response.text[start_index:end_index]
            else:
                mermaid_formula = response.text[start_index:]

            mermaid_formula = re.sub(r'([A-Z])\[', r'\n\1[', mermaid_formula)
            #text = st.write_stream(split_and_yield(mermaid_formula))

            stmd.st_mermaid(mermaid_formula, show_controls = False)
            print(mermaid_formula)
            
        st.session_state.messages.append({"role": "assistant", "content": mermaid_formula})