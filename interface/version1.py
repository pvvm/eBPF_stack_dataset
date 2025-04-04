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
    Consider that all pointers occupy 8 bytes. At the end of each node you add the total amount of bytes that the node.
    You don't give explanations, you only show the result of the mermaid graph. No extra messages other than the mermaid graph.
    Do not use parentheses, square brackets, and brackets inside the nodes' values.
    THE WHOLE OUTPUT MUST BE IN A SINGLE LINE
    Now, I will show you 2 examples, showing the input and expected output of each:
    Example 1:
    Input: SEC("xdp") int xdp_prog(struct xdp_md *ctx) { return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> Total: 8 ]
    Example 2:
    Input: SEC("xdp") int xdp_prog(struct xdp_md *ctx) { __u32 variable = 100; variable += 51; return XDP_DROP; // Drop all packets } char LICENSE[] SEC("license") = "GPL";
    Output: graph TD \n A[ <b> xdp_prog </b> <br> ctx -> 8 <br> variable -> 4 <br> Total: 12 ]
    """),
        ],
    )
    return generate_content_config



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