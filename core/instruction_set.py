from core.util import decompose_byte, twos_complement


class Instructions:
    def __init__(self, op) -> None:
        self.op = op
        self._jump_flag = False
        self._jump_instructions = op._jump_instructions
        self._base = 16
        self.flags = self.op.super_memory.PSW
        pass

    def _is_jump_opcode(self, opcode) -> bool:
        opcode = opcode.upper()
        if opcode not in self._jump_instructions:
            return False
        return True

    def _next_addr(self, addr) -> str:
        return format(int(str(addr), 16) + 1, "#06x")

    def _check_carry(self, data_1, data_2, og2, add=True, _AC=True, _CY=True) -> None:
        """
        Method to check both `CY` and `AC` self.flags.

        `aux_data` are the LSB of the two data to be added
        For example: for `0x11` and `0xae`, `aux_data=["0x1", "0xe"]`
        """
        decomposed_data_1 = decompose_byte(data_1, nibble=True)
        decomposed_data_2 = decompose_byte(data_2, nibble=True)
        carry_data, aux_data = list(zip(decomposed_data_1, decomposed_data_2))

        if _AC:
            self.flags.AC = False
            if (int(aux_data[0], 16) + int(aux_data[1], 16)) >= 16:
                print("AUX FLAG")
                self.flags.AC = True

        if not _CY:
            return

        if not add:
            self.flags.CY = False
            if int(str(data_1), 16) < int(str(og2), 16):
                print("CARRY FLAG-")
                self.flags.CY = True
        return

    def _check_parity(self, data_bin: str) -> None:
        self.flags.P = False
        _count_1s = data_bin.count("1")
        if not _count_1s % 2:
            self.flags.P = True
            print("PARITY")
        return

    def _check_overflow(self, data_bin: str) -> None:
        self.flags.OV = False
        if int(data_bin[0]):
            self.flags.OV = True
            print("SIGN")
        return

    def _check_flags(self, data_bin, _P=True, _OV=True) -> bool:
        if _P:
            self._check_parity(data_bin)
        if _OV:
            self._check_overflow(data_bin)
        return True

    def _check_flags_and_compute(self, data_1, data_2, add=True, _AC=True, _CY=True, _P=True, _OV=True):
        og2 = data_2
        if not add:
            data_2 = twos_complement(str(data_2))

        result = int(str(data_1), 16) + int(str(data_2), 16)
        if result > 255:
            if _CY:
                self.flags.CY = True
                print("CARRY FLAG+")
            result -= 256
        result_hex = format(result, "#04x")
        data_bin = format(result, "08b")

        self._check_carry(data_1, data_2, og2, add=add, _AC=_AC, _CY=_CY)
        self._check_flags(data_bin, _P=_P, _OV=_OV)
        return result_hex

    def _resolve_addressing_mode(self, addr, data=None) -> tuple:
        if addr[0] == "@":  # Register indirect
            addr = self.op.memory_read(addr[1:])

        if data:
            if data[0] == "@":  # Register indirect
                data = self.op.memory_read(data[1:])
            elif data[0] == "#":  # Immediate addressing
                data = data[1:]
            else:
                data = self.op.memory_read(data)
        return addr, data

    def mov(self, addr, data) -> bool:
        addr, data = self._resolve_addressing_mode(addr, data)
        return self.op.memory_write(addr, data)

    def add(self, addr, data) -> bool:
        addr, data_1 = self._resolve_addressing_mode(addr, data)
        data_2 = self.op.memory_read(addr)
        result_hex = self._check_flags_and_compute(data_1, data_2)
        return self.op.memory_write(addr, result_hex)

    def addc(self, addr, data) -> bool:
        """Add with carry"""
        addr, data_1 = self._resolve_addressing_mode(addr, data)
        data_2 = self.op.memory_read(addr)
        if self.flags.CY:
            data_2 = format(int(str(data_2), 16) + 1, "#04x")
        result_hex = self._check_flags_and_compute(data_1, data_2)
        return self.op.memory_write(addr, result_hex)

    def subb(self, addr, data) -> bool:
        addr, data_2 = self._resolve_addressing_mode(addr, data)
        data_1 = self.op.memory_read(addr)
        if self.flags.CY:
            self.flags.CY = False
            data_2 += 1
        result_hex = self._check_flags_and_compute(data_1, data_2, add=False)
        return self.op.memory_write(addr, result_hex)

    def anl(self, addr_1, addr_2) -> bool:
        addr_1, _ = self._resolve_addressing_mode(addr_1)
        addr_2, _ = self._resolve_addressing_mode(addr_2)

        data_1 = int(self.op.memory_read(addr_1))
        data_2 = int(self.op.memory_read(addr_2))
        result = format(data_1 & data_2, "#04x")
        self.op.memory_write(addr_1, result)
        return self._check_flags(format(int(result, self._base), "08b"))

    def orl(self, addr_1, addr_2) -> bool:
        addr_1, _ = self._resolve_addressing_mode(addr_1)
        addr_2, _ = self._resolve_addressing_mode(addr_2)

        data_1 = int(self.op.memory_read(addr_1))
        data_2 = int(self.op.memory_read(addr_2))
        result = format(data_1 | data_2, "#04x")
        self.op.memory_write(addr_1, result)
        return self._check_flags(format(int(result, self._base), "08b"))

    def inc(self, addr) -> bool:
        addr, _ = self._resolve_addressing_mode(addr)
        data = self.op.memory_read(addr)
        return self.op.memory_write(addr, data + 1)

    def dec(self, addr) -> bool:
        addr, _ = self._resolve_addressing_mode(addr)
        print(f"addr: {addr}")
        data = self.op.memory_read(addr)
        data_to_write = self._check_flags_and_compute(
            data, "0x01", add=False, _CY=False, _AC=False, _P=False, _OV=False
        )
        return self.op.memory_write(addr, data_to_write)

    def rlc(self, addr) -> bool:
        """Rotate left through carry"""
        addr, _ = self._resolve_addressing_mode(addr)
        data = int(self.op.memory_read(addr))
        data_bin = format(data, "08b")
        
        # Get current carry flag
        old_carry = 1 if self.flags.CY else 0
        
        # Rotate left through carry
        new_carry = int(data_bin[0])  # MSB becomes new carry
        rotated_data = data_bin[1:] + str(old_carry)  # Shift left and add old carry
        
        # Update carry flag
        self.flags.CY = bool(new_carry)
        
        # Write back rotated data
        data_new = format(int(rotated_data, 2), "#02x")
        return self.op.memory_write(addr, data_new)

    def rrc(self, addr) -> bool:
        """Rotate right through carry"""
        addr, _ = self._resolve_addressing_mode(addr)
        data = int(self.op.memory_read(addr))
        data_bin = format(data, "08b")
        
        # Get current carry flag
        old_carry = 1 if self.flags.CY else 0
        
        # Rotate right through carry
        new_carry = int(data_bin[-1])  # LSB becomes new carry
        rotated_data = str(old_carry) + data_bin[:-1]  # Add old carry and shift right
        
        # Update carry flag
        self.flags.CY = bool(new_carry)
        
        # Write back rotated data
        data_new = format(int(rotated_data, 2), "#02x")
        return self.op.memory_write(addr, data_new)

    def rl(self, addr) -> bool:
        """Rotate left without carry"""
        addr, _ = self._resolve_addressing_mode(addr)
        data = self.op.memory_read(addr)
        data_bin = list(format(int(str(data), 16), "08b"))
        rolled_data_bin = []

        for i in range(0, len(data_bin[:-1])):
            rolled_data_bin.append(data_bin[i + 1])

        rolled_data_bin.insert(8, str(int(data_bin[0])))
        rolled_data_bin = "".join(rolled_data_bin)
        data_new = format(int(rolled_data_bin, 2), "#02x")
        return self.op.memory_write("A", data_new)

    def rr(self, addr) -> bool:
        """Rotate right without carry"""
        addr, _ = self._resolve_addressing_mode(addr)
        data = self.op.memory_read(addr)
        data_bin = list(format(int(str(data), 16), "08b"))
        rolled_data_bin = []
        rolled_data_bin.insert(0, str(int(data_bin[7])))
        for i in range(0, len(data_bin[:-1])):
            rolled_data_bin.append(data_bin[i])

        rolled_data_bin = "".join(rolled_data_bin)
        data_new = format(int(rolled_data_bin, 2), "#02x")
        return self.op.memory_write("A", data_new)

    def div(self) -> bool:
        """Divide A by B, result in A, remainder in B"""
        a_val = int(self.op.memory_read("A"))
        b_val = int(self.op.memory_read("B"))
        if b_val == 0:
            # Division by zero - undefined behavior, set flags
            self.flags.OV = True
            return False
        quotient = a_val // b_val
        remainder = a_val % b_val
        self.op.memory_write("A", f"0x{quotient:02x}")
        self.op.memory_write("B", f"0x{remainder:02x}")
        self.flags.OV = False
        self.flags.CY = False
        return True

    def mul(self) -> bool:
        """Multiply A by B, result in A:B"""
        a_val = int(self.op.memory_read("A"))
        b_val = int(self.op.memory_read("B"))
        result = a_val * b_val
        
        # Store low byte in A, high byte in B
        self.op.memory_write("A", f"0x{result & 0xFF:02x}")
        self.op.memory_write("B", f"0x{(result >> 8) & 0xFF:02x}")
        
        # Set overflow flag if result > 255
        self.flags.OV = result > 255
        self.flags.CY = False
        return True

    def xrl(self, addr_1, addr_2) -> bool:
        """Exclusive OR logical operation"""
        addr_1, _ = self._resolve_addressing_mode(addr_1)
        addr_2, _ = self._resolve_addressing_mode(addr_2)

        data_1 = int(self.op.memory_read(addr_1))
        data_2 = int(self.op.memory_read(addr_2))
        result = format(data_1 ^ data_2, "#04x")
        self.op.memory_write(addr_1, result)
        return self._check_flags(format(int(result, self._base), "08b"))

    def xch(self, addr_1, addr_2) -> bool:
        """Exchange bytes between accumulator and register/memory"""
        # XCH is typically between A and another register/memory location
        if addr_1.upper() != "A":
            addr_1, addr_2 = addr_2, addr_1  # Ensure A is first
        
        addr_2, _ = self._resolve_addressing_mode(addr_2)
        a_val = self.op.memory_read("A")
        data_val = self.op.memory_read(addr_2)
        
        # Swap the values
        self.op.memory_write("A", data_val)
        self.op.memory_write(addr_2, a_val)
        return True

    def xchd(self, addr) -> bool:
        """Exchange low-order digit of accumulator with register/memory"""
        addr, _ = self._resolve_addressing_mode(addr)
        a_val = int(self.op.memory_read("A"))
        data_val = int(self.op.memory_read(addr))
        
        # Exchange low nibbles (lower 4 bits)
        a_low = a_val & 0x0F
        data_low = data_val & 0x0F
        
        new_a = (a_val & 0xF0) | data_low
        new_data = (data_val & 0xF0) | a_low
        
        self.op.memory_write("A", f"0x{new_a:02x}")
        self.op.memory_write(addr, f"0x{new_data:02x}")
        return True

    def swap(self, addr) -> bool:
        """Swap nibbles in accumulator"""
        addr, _ = self._resolve_addressing_mode(addr)
        data = int(self.op.memory_read(addr))
        
        # Swap high and low nibbles
        high_nibble = (data >> 4) & 0x0F
        low_nibble = data & 0x0F
        swapped = (low_nibble << 4) | high_nibble
        
        return self.op.memory_write(addr, f"0x{swapped:02x}")

    def da(self, addr: str) -> bool:
        """Converts the hex data into its BCD equivalent."""
        addr, _ = self._resolve_addressing_mode(addr)
        data = self.op.memory_read(addr)
        data_decimal = int(str(data), 16)
        return self.op.memory_write(addr, f"0x{data_decimal}")

    def org(self, addr) -> bool:
        """Database directive origin"""
        return self.op.super_memory.PC(addr)

    def setb(self, bit: str) -> bool:
        """Set a bit to true"""
        return self.op.bit_write(bit, True)

    def clr(self, bit: str) -> bool:
        """Clears a bit"""
        return self.op.bit_write(bit, False)

    def cpl(self, bit: str) -> bool:
        """Complements a bit"""
        _data = self.op.bit_read(bit)
        return self.op.bit_write(bit, not _data)

    def push(self, addr: str) -> bool:
        """Pushes the content of the memory location to the stack."""
        data = self.op.memory_read(addr)
        return self.op.super_memory.SP.write(data)

    def pop(self, addr: str) -> bool:
        """Pop the stack as the content of the memory location."""
        data = self.op.super_memory.SP.read()
        return self.op.memory_write(addr, data)

    def jz(self, label, *args, **kwargs) -> bool:
        """Jump if accumulator is zero"""
        bounce_to_label = kwargs.get("bounce_to_label")
        print(self.op.memory_read("A"))
        if int(self.op.memory_read("A")) == 0:
            return bounce_to_label(label)
        return True

    def jnz(self, label, *args, **kwargs) -> bool:
        """Jump if accumulator is not zero"""
        bounce_to_label = kwargs.get("bounce_to_label")
        print(self.op.memory_read("A"))
        if int(self.op.memory_read("A")) != 0:
            return bounce_to_label(label)
        return True

    def jc(self, label, *args, **kwargs) -> bool:
        """Jump if carry"""
        bounce_to_label = kwargs.get("bounce_to_label")
        print(self.op.flags.CY)
        if self.op.flags.CY:
            return bounce_to_label(label)
        return True

    def jnc(self, label, *args, **kwargs) -> bool:
        """Jump if no carry"""
        bounce_to_label = kwargs.get("bounce_to_label")
        print(self.op.flags.CY)
        if not self.op.flags.CY:
            return bounce_to_label(label)
        return True

    def djnz(self, addr, label, *args, **kwargs) -> bool:
        """Jump if accumulator is not zero"""
        bounce_to_label = kwargs.get("bounce_to_label")
        if label == "offset":
            label = addr
            addr = "A"
        data = self.op.memory_read(addr)

        result = int(str(data), 16) - 1
        self.op.memory_write(addr, hex(result))
        if int(self.op.memory_read(addr)) != 0:
            return bounce_to_label(label)
        return True

    def jb(self, bit, label, *args, **kwargs) -> bool:
        """Jump if bit is true"""
        bounce_to_label = kwargs.get("bounce_to_label")
        bit_val = self.op.bit_read(bit)
        if bit_val:
            return bounce_to_label(label)
        return True

    def jnb(self, bit, label, *args, **kwargs) -> bool:
        """Jump if bit is false"""
        bounce_to_label = kwargs.get("bounce_to_label")
        bit_val = self.op.bit_read(bit)
        if not bit_val:
            return bounce_to_label(label)
        return True

    def jbc(self, bit, label, *args, **kwargs) -> bool:
        """Jump if bit is true and clear the bit"""
        bounce_to_label = kwargs.get("bounce_to_label")
        bit_val = self.op.bit_read(bit)
        if bit_val:
            self.op.bit_write(bit, False)  # Clear the bit
            return bounce_to_label(label)
        return True

    def cjne(self, addr, addr2, label, *args, **kwargs) -> bool:
        """Compare and jump if not equal"""
        bounce_to_label = kwargs.get("bounce_to_label")
        data_1 = self.op.memory_read(addr)
        addr2, _ = self._resolve_addressing_mode(addr2)
        data_2 = self.op.memory_read(addr2)
        if int(data_1) != int(data_2):
            if int(data_1) < int(data_2):
                self.flags.CY = True
            # Jump if not equal
            return bounce_to_label(label)
        self.flags.CY = False
        return True

    def acall(self, addr) -> bool:
        """Absolute call within 2K page"""
        # Push current PC to stack
        current_pc = int(self.op.super_memory.PC.read())
        high_pc = (current_pc >> 8) & 0xFF
        low_pc = current_pc & 0xFF
        
        self.op.super_memory.SP.write(f"0x{high_pc:02x}")
        self.op.super_memory.SP.write(f"0x{low_pc:02x}")
        
        # Jump to target address (simplified - ignoring 2K page restrictions)
        return self.op.super_memory.PC(addr)

    def lcall(self, addr) -> bool:
        """Long call to 16-bit address"""
        # Push current PC to stack
        current_pc = int(self.op.super_memory.PC.read())
        high_pc = (current_pc >> 8) & 0xFF
        low_pc = current_pc & 0xFF
        
        self.op.super_memory.SP.write(f"0x{high_pc:02x}")
        self.op.super_memory.SP.write(f"0x{low_pc:02x}")
        
        # Jump to target address
        return self.op.super_memory.PC(addr)

    def ret(self) -> bool:
        """Return from subroutine"""
        # Pop return address from stack
        low_pc = int(self.op.super_memory.SP.read())
        high_pc = int(self.op.super_memory.SP.read())
        return_addr = (high_pc << 8) | low_pc
        
        return self.op.super_memory.PC(f"0x{return_addr:04x}")

    def reti(self) -> bool:
        """Return from interrupt"""
        # Similar to RET but also restores interrupt logic
        # For now, implement same as RET
        return self.ret()

    def movx(self, addr, data=None) -> bool:
        """Move data between accumulator and external data memory"""
        if data is None:
            # MOVX A, @DPTR or MOVX A, @R0/R1 (read from external memory)
            if addr.upper() == "@DPTR":
                dptr_val = int(self.op.memory_read("DPTR"))
                # For simulation, use internal memory as external memory
                data = self.op.memory_read(f"0x{dptr_val:04x}")
                return self.op.memory_write("A", data)
            elif addr.startswith("@R"):
                reg_num = addr[2]
                reg_val = int(self.op.memory_read(f"R{reg_num}"))
                data = self.op.memory_read(f"0x{reg_val:02x}")
                return self.op.memory_write("A", data)
        else:
            # MOVX @DPTR, A or MOVX @R0/R1, A (write to external memory)
            data_val = self.op.memory_read("A")
            if addr.upper() == "@DPTR":
                dptr_val = int(self.op.memory_read("DPTR"))
                return self.op.memory_write(f"0x{dptr_val:04x}", data_val)
            elif addr.startswith("@R"):
                reg_num = addr[2]
                reg_val = int(self.op.memory_read(f"R{reg_num}"))
                return self.op.memory_write(f"0x{reg_val:02x}", data_val)
        return False

    def movc(self, addr, data=None) -> bool:
        """Move data from code memory to accumulator"""
        if data is None:
            # MOVC A, @A+DPTR or MOVC A, @A+PC
            if addr.upper() == "@A+DPTR":
                a_val = int(self.op.memory_read("A"))
                dptr_val = int(self.op.memory_read("DPTR"))
                code_addr = dptr_val + a_val
                # For simulation, use internal memory as code memory
                data = self.op.memory_read(f"0x{code_addr:04x}")
                return self.op.memory_write("A", data)
            elif addr.upper() == "@A+PC":
                a_val = int(self.op.memory_read("A"))
                pc_val = int(self.op.super_memory.PC.read())
                code_addr = pc_val + a_val
                data = self.op.memory_read(f"0x{code_addr:04x}")
                return self.op.memory_write("A", data)
        return False

    def clr_a(self) -> bool:
        """Clear accumulator"""
        return self.op.memory_write("A", "0x00")

    def setb_c(self) -> bool:
        """Set carry flag"""
        self.flags.CY = True
        return True

    def clr_c(self) -> bool:
        """Clear carry flag"""
        self.flags.CY = False
        return True

    def cpl_a(self) -> bool:
        """Complement accumulator"""
        a_val = int(self.op.memory_read("A"))
        complemented = (~a_val) & 0xFF  # Keep only 8 bits
        return self.op.memory_write("A", f"0x{complemented:02x}")

    def jmp(self, addr) -> bool:
        """Unconditional jump to address"""
        return self.op.super_memory.PC(addr)

    def nop(self) -> bool:
        """No operation"""
        return True

    pass
