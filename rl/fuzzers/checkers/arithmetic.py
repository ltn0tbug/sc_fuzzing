from .checker import Checker
from ...ethereum import ADD, MUL, SUB


# class ArithmeticChecker:
#     """
#     Checker for arithmetic overflow/underflow in EVM execution logs.
#     It inspects ADD, SUB, and MUL opcodes for wrap-around bugs.
#     Assumes 256-bit arithmetic (Solidity/EVM). For Solidity >=0.8,
#     only use this checker in `unchecked` context, since normal arithmetic
#     reverts on overflow by default:contentReference[oaicite:4]{index=4}.
#     """
#     def __init__(self):
#         # Constants for 256-bit and signed 256-bit bounds
#         self.MODULUS = 2**256
#         self.INT_MAX = 2**255 - 1
#         self.INT_MIN = -2**255

#     @staticmethod
#     def to_signed(value):
#         """
#         Convert an unsigned 256-bit integer (0 <= value < 2^256) to signed int256.
#         In two's complement, values >= 2^255 represent negatives.
#         """
#         if value >= 2**255:
#             return value - 2**256
#         else:
#             return value

#     def detect(self, op, stack):
#         """
#         Check a single EVM operation for overflow/underflow.

#         Args:
#             op (str): EVM opcode name, e.g., 'ADD', 'SUB', 'MUL'.
#             stack (list of str): Current stack as hex strings (top at stack[-1]).

#         Returns:
#             bool: True if an arithmetic wrap-around bug is detected.
#         """
#         # Only interested in arithmetic opcodes
#         if op not in ('ADD', 'SUB', 'MUL'):
#             return False

#         # Need at least two stack items for binary ops
#         if len(stack) < 2:
#             return False

#         # Parse the two top values as unsigned integers
#         a = int(stack[-2], 16)
#         b = int(stack[-1], 16)

#         # UNSIGNED arithmetic checks:
#         if op == 'ADD':
#             # Overflow if a + b >= 2^256
#             if a + b >= self.MODULUS:
#                 return True
#         elif op == 'SUB':
#             # Underflow if subtract larger (wrap-around)
#             if a < b:
#                 return True
#         elif op == 'MUL':
#             # Overflow if non-zero and product >= 2^256
#             if a != 0 and (a * b) >= self.MODULUS:
#                 return True

#         # SIGNED arithmetic checks:
#         # Convert to signed int256
#         signed_a = self.to_signed(a)
#         signed_b = self.to_signed(b)
#         # Compute signed result (mathematically, Python int has no overflow)
#         if op == 'ADD':
#             signed_res = signed_a + signed_b
#         elif op == 'SUB':
#             signed_res = signed_a - signed_b
#         else:  # op == 'MUL'
#             signed_res = signed_a * signed_b

#         # If result is out of int256 range, that's an overflow/underflow
#         if signed_res > self.INT_MAX or signed_res < self.INT_MIN:
#             return True


#         # No overflow detected
#         return False
class Arithmetic(Checker):
    def __init__(self):
        super().__init__()
        self.MODULUS = 2**256
        self.INT_MAX = 2**255 - 1
        self.INT_MIN = -(2**255)

    # @staticmethod
    # def to_signed(value):
    #     """
    #     Convert an unsigned 256-bit integer (0 <= value < 2^256) to signed int256.
    #     In two's complement, values >= 2^255 represent negatives.
    #     """
    #     if value >= 2**255:
    #         return value - 2**256
    #     else:
    #         return value

    def check(self, logger):
        for log in logger.logs:
            op = log.op
            stack = log.stack
            if op not in (ADD, SUB, MUL):
                continue

            # Need at least two stack items for binary ops
            if len(stack) < 2:
                continue

            # Parse the two top values as unsigned integers
            a = int(stack[-2], 16)
            b = int(stack[-1], 16)

            # UNSIGNED arithmetic checks:
            if op == ADD:
                # Overflow if a + b >= 2^256
                if a + b >= self.MODULUS:
                    print(a, b)
                    return True
            elif op == SUB:
                # Underflow if subtract larger (wrap-around)
                if a < b:
                    print(a, b)
                    return True
            elif op == MUL:
                # Overflow if non-zero and product >= 2^256
                if a != 0 and (a * b) >= self.MODULUS:
                    print(a, b)
                    return True

            # # SIGNED arithmetic checks:
            # # Convert to signed int256
            # signed_a = self.to_signed(a)
            # signed_b = self.to_signed(b)
            # # Compute signed result (mathematically, Python int has no overflow)
            # if op == ADD:
            #     signed_res = signed_a + signed_b
            # elif op == SUB:
            #     signed_res = signed_a - signed_b
            # else:  # op == 'MUL'
            #     signed_res = signed_a * signed_b

            # # If result is out of int256 range, that's an overflow/underflow
            # if signed_res > self.INT_MAX or signed_res < self.INT_MIN:
            #     return True

        # No overflow detected
        return False


# class Arithmetic(Checker):
#     def __init__(self):
#         super().__init__()

#     def check(self, logger):
#         for i, log in enumerate(logger.logs):
#             # Checking for overflow in ADD and MUL
#             if log.op in (ADD, MUL):
#                 try:
#                     op1 = int(log.stack[-1], 16)
#                     op2 = int(log.stack[-2], 16)

#                     if log.op == ADD:
#                         result = op1 + op2
#                     elif log.op == MUL:
#                         result = op1 * op2

#                     # Check if result is less than either operand (indicates overflow)
#                     if result < op1 or result < op2:
#                         return True
#                 except (ValueError, IndexError):
#                     # Stack access failure or invalid values
#                     continue

#             # Checking for underflow in SUB
#             elif log.op == SUB:
#                 try:
#                     op1 = int(log.stack[-1], 16)
#                     op2 = int(log.stack[-2], 16)

#                     # Check for underflow (op2 should not be greater than op1)
#                     if op2 > op1:
#                         return True
#                 except (ValueError, IndexError):
#                     # Stack access failure or invalid values
#                     continue

#         return False
