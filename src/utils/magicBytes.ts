// Magic bytes for blocked executable file types
const BLOCKED_SIGNATURES: { name: string; bytes: number[] }[] = [
  // Windows executables
  { name: 'exe/dll (MZ)', bytes: [0x4D, 0x5A] }, // MZ header
  // Linux ELF
  { name: 'ELF', bytes: [0x7F, 0x45, 0x4C, 0x46] }, // \x7FELF
  // macOS Mach-O (32-bit)
  { name: 'Mach-O 32-bit', bytes: [0xFE, 0xED, 0xFA, 0xCE] },
  // macOS Mach-O (64-bit)
  { name: 'Mach-O 64-bit', bytes: [0xFE, 0xED, 0xFA, 0xCF] },
  // macOS Mach-O (32-bit reverse)
  { name: 'Mach-O 32-bit (reverse)', bytes: [0xCE, 0xFA, 0xED, 0xFE] },
  // macOS Mach-O (64-bit reverse)
  { name: 'Mach-O 64-bit (reverse)', bytes: [0xCF, 0xFA, 0xED, 0xFE] },
  // macOS Universal Binary
  { name: 'Mach-O Universal', bytes: [0xCA, 0xFE, 0xBA, 0xBE] },
  // Windows Installer (MSI is actually a Compound Document)
  { name: 'MSI/Compound Document', bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
];

// Shebang patterns for scripts
const SHEBANG_BYTES = [0x23, 0x21]; // #!

export type ValidationResult = {
  valid: boolean;
  reason?: string;
};

export function validateMagicBytes(bytes: Uint8Array): ValidationResult {
  // Check for shebang (scripts)
  if (bytes.length >= 2 && bytes[0] === SHEBANG_BYTES[0] && bytes[1] === SHEBANG_BYTES[1]) {
    return {
      valid: false,
      reason: 'Executable scripts are not allowed'
    };
  }

  // Check blocked signatures
  for (const sig of BLOCKED_SIGNATURES) {
    if (bytes.length >= sig.bytes.length) {
      let match = true;
      for (let i = 0; i < sig.bytes.length; i++) {
        if (bytes[i] !== sig.bytes[i]) {
          match = false;
          break;
        }
      }
      if (match) {
        return {
          valid: false,
          reason: `Executable files (${sig.name}) are not allowed`
        };
      }
    }
  }

  return { valid: true };
}
