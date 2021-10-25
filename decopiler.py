import io
import logging
import os
import sys
import traceback
from contextlib import redirect_stdout

import coloredlogs
import timeout_decorator

import pano.folder as folder
from pano.contract import Contract
from pano.function import Function
from pano.loader import Loader
from pano.prettify import explain, pprint_repr, pprint_trace, pretty_type
from pano.vm import VM
from pano.whiles import make_whiles
from utils.helpers import C, cache_fname, rewrite_trace

logging.getLogger("pano.matcher").setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG,
    format="%(asctime)s %(filename)s %(levelname)s %(message)s",
    datefmt='%a %d %b %Y %H:%M:%S')
code = "0x606060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632a0f76961461005c5780635b6b431d1461009f5780639f1b3bad146100c2575b600080fd5b341561006757600080fd5b610081600480803561ffff169060200190919050506100cc565b60405180826000191660001916815260200191505060405180910390f35b34156100aa57600080fd5b6100c06004808035906020019091905050610138565b005b6100ca6101d6565b005b60006001546001900461ffff168261ffff16141561012b57600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050610133565b600060010290505b919050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561019357600080fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f1935050505015156101d357600080fd5b50565b6000806002346000604051602001526040518082815260200191505060206040518083038160008661646e5a03f1151561020f57600080fd5b50506040518051905091506001548218905080600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020816000191690555050505600a165627a7a723058204760a4fe708c70459c1c33c4668609c3f1a8cf0a82d2fc7786c343457dbb55c30029"
loader = Loader()
loader.load_binary(code)
loader.run(VM(loader, just_fdests=True))
if len(loader.lines) == 0:
    # No code.
    logging.warning("# No code found for this contract." )

problems = {}
functions = {}

for (hash, fname, target, stack) in loader.func_list:
    """
        hash contains function hash
        fname contains function name
        target contains line# for the given function
    """
    logging.info(f"Parsing %s...", fname)
    logging.debug("stack %s", stack)
    try:
        if target > 1 and loader.lines[target][1] == "jumpdest":
            target += 1

        @timeout_decorator.timeout(120, use_signals=True)
        def dec():
            trace = VM(loader).run(target, stack=stack)
            logging.info("Initial decompiled trace")

            trace = make_whiles(trace)
            return trace
        trace = dec()

        functions[hash] = Function(hash, trace)

    except Exception as e:
        problems[hash] = fname
        logging.error(f"Problem with %s%s\n%s", fname, C.end, traceback.format_exc())

contract = Contract(problems=problems, functions=functions,)

contract.postprocess()

text_output = io.StringIO()
with redirect_stdout(text_output):

    """
        Print out decompilation header
    """

    print("# Palkeoramix decompiler. ")

    if len(problems) > 0:
        print("#")
        print("#  I failed with these: ")
        for p in problems.values():
            print(f"#  - {p}")
        print("#  All the rest is below.")
        print("#")

    print()

    """
        Print out constants & storage
    """

    shown_already = set()

    logging.info("len(contract.stor_defs) = "+ str(len(functions.items())) +"a"+ str(len(contract.consts)))
    for func in contract.consts:
        logging.debug("hash: " + func.hash)
        shown_already.add(func.hash)
        func.print()

    if shown_already:
        print()

    if len(contract.stor_defs) > 0:
        print(f"def storage:")

        for s in contract.stor_defs:
            print(pretty_type(s))

        print()

    """
        Print out getters
    """

    for hash, func in functions.items():
        if func.getter is not None:
            shown_already.add(hash)
            print(func.print())

            print()

    """
        Print out regular functions
    """

    func_list = list(contract.functions)
    func_list.sort(
        key=lambda f: f.priority()
    )  # sort func list by length, with some caveats

    if shown_already and any(1 for f in func_list if f.hash not in shown_already):
        # otherwise no irregular functions, so this is not needed :)
        print("#\n#  Regular functions\n#" + "\n")

    for func in func_list:
        hash = func.hash

        if hash not in shown_already:
            shown_already.add(hash)

            print(func.print())

            print()

text = text_output.getvalue()
text_output.close()
print(text)