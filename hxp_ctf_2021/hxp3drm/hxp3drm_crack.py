#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP CTF 2021 - hxp3drm (RE - 714pt)
# ----------------------------------------------------------------------------------------
import hashlib
from Crypto.Cipher import AES


flag_ASCII_ciphertext = [
  0xBB, 0x0A, 0xA5, 0x80, 0x4B, 0xCE, 0xEA, 0x06, 0x7D, 0xBA, 0xBD, 0x0F, 0xB6, 0xB2, 0x6E, 0xE6, 0xF2, 0x10, 0xB6, 0x68, 
  0xA7, 0x06, 0xC2, 0x90, 0x0E, 0x52, 0xE2, 0xAA, 0x56, 0x9E, 0xA6, 0x9F, 0x17, 0x7B, 0x1C, 0x51, 0x75, 0x1F, 0x6B, 0x18, 
  0x72, 0xA2, 0x84, 0xCB, 0xAB, 0xAC, 0xC1, 0x3E, 0x34, 0x78, 0x4D, 0xE9, 0xF6, 0x03, 0xAD, 0x99, 0xE9, 0xB2, 0x7D, 0x83, 
  0xFA, 0x76, 0xE0, 0xC6, 0xE4, 0x31, 0x74, 0xD0, 0xDD, 0x78, 0x86, 0xE7, 0xE8, 0x24, 0xB6, 0x1C, 0xC0, 0xE7, 0xB7, 0xE9, 
  0xCD, 0x36, 0x5B, 0xB2, 0x4D, 0x1F, 0x1E, 0x29, 0x69, 0x84, 0x9D, 0xBC, 0x32, 0x01, 0x42, 0x13, 0x7F, 0x10, 0x0A, 0x05, 
  0x75, 0x24, 0xF2, 0x1A, 0xBD, 0xC0, 0x3D, 0x6C, 0x73, 0x66, 0xDF, 0xC3, 0x40, 0xFE, 0x07, 0xA3, 0x0E, 0x14, 0xD5, 0xFE, 
  0x2B, 0xE9, 0xC0, 0x2A, 0xF0, 0x8E, 0xB6, 0xD2, 0xF4, 0x62, 0xFA, 0x89, 0x58, 0xDE, 0xEE, 0x8E, 0x89, 0xA0, 0x79, 0x4E, 
  0x83, 0x20, 0xDC, 0x61, 0x2D, 0x11, 0x96, 0xF8, 0x42, 0x16, 0xF5, 0x38, 0xD0, 0xA4, 0xC5, 0xF4, 0xCD, 0x68, 0x33, 0xDD, 
  0x27, 0xAC, 0xAF, 0x13, 0x62, 0x90, 0x69, 0xD6, 0x04, 0x28, 0x5C, 0x13, 0x5B, 0x12, 0x4A, 0x41, 0x29, 0xCA, 0xF7, 0x0D, 
  0xB4, 0x7D, 0x75, 0x76, 0x78, 0xB1, 0x43, 0xD7, 0xB8, 0x95, 0x28, 0x20, 0xA6, 0x6A, 0x1E, 0xF4, 0x2D, 0x56, 0x29, 0x56, 
  0xEB, 0x9E, 0xC1, 0x96, 0x0D, 0x07, 0xB9, 0x0B, 0xD6, 0x62, 0x76, 0xAC, 0x62, 0x90, 0x5E, 0x98, 0x6A, 0xDF, 0x66, 0xC8, 
  0x43, 0x0C, 0xD2, 0x13, 0x69, 0x45, 0x49, 0x48, 0xFF, 0x13, 0xB6, 0x1B, 0xD4, 0x38, 0x7C, 0x9D, 0x7E, 0xF1, 0x61, 0x4C, 
  0x8D, 0x28, 0x6F, 0x82, 0x0A, 0x38, 0xAE, 0x94, 0xB8, 0xB8, 0x86, 0x45, 0xE1, 0xFE, 0x97, 0x10, 0xDB, 0xD0, 0x5D, 0x65, 
  0x52, 0x74, 0x89, 0xD6, 0xB3, 0xBB, 0x69, 0x9F, 0x76, 0xCA, 0xBE, 0xE5, 0x4C, 0x68, 0x33, 0xD1, 0x0F, 0xDC, 0xD3, 0x44, 
  0xBA, 0x4F, 0x61, 0x60, 0x92, 0x58, 0x28, 0x3E, 0x0A, 0xDC, 0xB3, 0x36, 0xE4, 0xDD, 0xC9, 0xA8, 0x21, 0x3A, 0xDA, 0x43, 
  0x0B, 0x2B, 0xED, 0x2D, 0x8D, 0x50, 0xFD, 0xC0, 0x73, 0xCF, 0xAC, 0x28, 0x1D, 0xE8, 0x0B, 0x96, 0xF4, 0xE8, 0x44, 0x10, 
  0x76, 0x16, 0xF4, 0x9A, 0x09, 0xE7, 0xB3, 0x4C, 0x0C, 0x8A, 0x24, 0x35, 0xA4, 0xEB, 0x77, 0x56, 0x69, 0x9F, 0x35, 0x3F, 
  0xE1, 0x9B, 0x37, 0x3F, 0xF5, 0x2B, 0xC6, 0x9D, 0x1F, 0x85, 0x63, 0x50, 0xCD, 0x46, 0xB0, 0x63, 0x70, 0x93, 0x5B, 0x32, 
  0x1C, 0x63, 0x11, 0x54, 0xB2, 0x99, 0x4F, 0xF1, 0x69, 0xD4, 0x9A, 0xCA, 0x36, 0x77, 0xEB, 0x3D, 0x12, 0xBE, 0x28, 0x61, 
  0x48, 0xE6, 0x3D, 0x74, 0x53, 0xE9, 0x90, 0x48, 0xA9, 0xA0, 0x67, 0x42, 0xAB, 0x2A, 0x22, 0xCA, 0xC3, 0x46, 0x74, 0x88, 
  0x36, 0x82, 0x5B, 0xF4, 0xEA, 0xE0, 0xE7, 0x58, 0xA7, 0x73, 0xFE, 0x8E, 0x12, 0x05, 0xC5, 0x9D, 0xB7, 0xDF, 0x1E, 0x53, 
  0x74, 0x35, 0x48, 0xEA, 0x28, 0x42, 0x7A, 0x6A, 0x92, 0xE5, 0x97, 0xD6, 0xE5, 0x66, 0xE1, 0x85, 0x07, 0x00, 0xA3, 0x6C, 
  0x65, 0x5A, 0x23, 0x8B, 0x08, 0x7D, 0x29, 0x11, 0xAD, 0xDE, 0x37, 0x57, 0xB3, 0xD4, 0x6D, 0xD1, 0x88, 0x1F, 0xC0, 0xF2, 
  0x80, 0x00, 0x1B, 0xB6, 0xBD, 0x6C, 0x06, 0xFF, 0x1C, 0xF7, 0x8F, 0xAD, 0xB5, 0xD7, 0x8A, 0xAE, 0xA6, 0xE7, 0x22, 0xE4, 
  0x9A, 0x42, 0x6A, 0xB8, 0x15, 0x78, 0x4B, 0x80, 0x11, 0x87, 0x20, 0xD4, 0xEA, 0xDD, 0x1C, 0x74, 0xAD, 0x16, 0x3A, 0x35, 
  0x8B, 0x0E, 0x11, 0x45, 0xE9, 0x61, 0x02, 0x99, 0xE3, 0x06, 0x12, 0xF4, 0xCD, 0x8F, 0x4F, 0x5E, 0xC7, 0x51, 0xA7, 0xE1, 
  0xFD, 0xEB, 0xC1, 0x93, 0x2A, 0x02, 0x8D, 0xB6, 0x67, 0xBF, 0x88, 0x94, 0x2D, 0x3A, 0xAE, 0xA5, 0x86, 0x75, 0xC3, 0x44, 
  0x93, 0x98, 0x70, 0x50, 0x1C, 0xF3, 0xB3, 0xAE, 0x6A, 0xEA, 0x18, 0xC9, 0xBE, 0x55, 0xEB, 0x20, 0x9E, 0xDC, 0x8C, 0xC0, 
  0xA2, 0x4E, 0xFF, 0x1C, 0xBD, 0xCE, 0x84, 0x73, 0x76, 0x74, 0x82, 0x0B, 0x0A, 0x31, 0x43, 0xCD, 0xCF, 0xCA, 0x70, 0x66, 
  0xC8, 0x52, 0x6E, 0xD2, 0x6A, 0xA8, 0x56, 0x87, 0x0C, 0x3A, 0xCC, 0x7D, 0x74, 0xD4, 0x59, 0xE9, 0x2C, 0x48, 0x9B, 0x7A, 
  0x8A, 0x9B, 0x10, 0x02, 0xD4, 0xD9, 0x84, 0x42, 0xF4, 0x14, 0xEA, 0x42, 0xFB, 0xB4, 0x73, 0x90, 0x6F, 0x13, 0x06, 0x8B, 
  0x80, 0x50, 0x35, 0x52, 0x1A, 0x96, 0xFB, 0x4A, 0x7C, 0x1A, 0xF0, 0xF9, 0x9C, 0xF5, 0x8A, 0x21, 0x0F, 0xE8, 0x85, 0x81, 
  0x86, 0x24, 0x6B, 0xE8, 0xEF, 0x8E, 0x70, 0x85, 0x6A, 0x02, 0x9F, 0x86, 0x22, 0x92, 0x11, 0xC8, 0xA8, 0x0F, 0xE0, 0xD0, 
  0x06, 0x1E, 0x89, 0xBE, 0x50, 0x6F, 0xF5, 0x87, 0x41, 0x39, 0x6E, 0xB4, 0x1C, 0x64, 0x59, 0xCD, 0x07, 0x3E, 0xE6, 0x90, 
  0x6B, 0x48, 0x6C, 0xFF, 0x7C, 0xE6, 0x99, 0xCA, 0x4B, 0x8B, 0x77, 0x21, 0x01, 0x2B, 0x2F, 0x84, 0x67, 0xA3, 0x82, 0x68, 
  0x8F, 0x8E, 0xCB, 0xB5, 0x16, 0x3C, 0x5C, 0x77, 0x00, 0x95, 0xDE, 0x14, 0x5E, 0x78, 0x8B, 0x6A, 0x54, 0x53, 0x0F, 0x3D, 
  0x89, 0xF3, 0xB8, 0x8B, 0x0B, 0xE0, 0xF1, 0xBD, 0xAE, 0x8C, 0x44, 0x49, 0xDB, 0x7A, 0xD5, 0x43, 0x7A, 0x92, 0x13, 0x8D, 
  0x7A, 0x64, 0x4D, 0x35, 0x65, 0x97, 0x5E, 0xFA, 0x02, 0xCC, 0x01, 0xCC, 0x7F, 0x49, 0x86, 0x22, 0x0B, 0xCE, 0x91, 0x13, 
  0x8F, 0xF4, 0x74, 0x3E, 0xA8, 0x3A, 0xDC, 0xD2, 0x44, 0x99, 0x13, 0x39, 0x22, 0x23, 0x96, 0x77, 0xB6, 0x9D, 0xEC, 0x06, 
  0xF4, 0x42, 0x14, 0xED, 0x6E, 0x09, 0x54, 0x68, 0xE4, 0x11, 0x17, 0x7E, 0xFB, 0xD0, 0x3F, 0x50, 0xA6, 0x91, 0xEF, 0x49, 
  0xCA, 0xDB, 0xFD, 0x7C, 0x9A, 0x5F, 0x40, 0x17, 0xF3, 0x58, 0x38, 0xBB, 0x32, 0x7E, 0x72, 0xCD, 0x71, 0x9E, 0x8B, 0xE7, 
  0x88, 0xC8, 0x87, 0x4B, 0xE5, 0x87, 0x7C, 0x8C, 0x60, 0x28, 0x01, 0x28, 0x66, 0xEF, 0xA7, 0x86, 0xB2, 0x9D, 0xFE, 0x9E, 
  0xCD, 0xA5, 0x67, 0xE4, 0xB1, 0x1D, 0xD8, 0x3F, 0x0D, 0xA7, 0x1E, 0x1F, 0xDF, 0xFD, 0x3D, 0x6A, 0xED, 0xCE, 0x2E, 0x14, 
  0x50, 0xCD, 0xA2, 0xAF, 0xE0, 0xB7, 0x5A, 0x41, 0xE5, 0xCE, 0xDC, 0x52, 0xE5, 0xDA, 0xB7, 0x45, 0xF6, 0x95, 0x31, 0x4F, 
  0x51, 0xCA, 0xCE, 0xC4, 0x19, 0x17, 0x6A, 0xE5, 0x04, 0x66, 0xEC, 0xF5, 0x74, 0x24, 0xC4, 0x11, 0x44, 0x7D, 0x02, 0x3D, 
  0x9B, 0x2A, 0xC4, 0x23, 0xB0, 0xD4, 0xC7, 0x1F, 0xA9, 0x90, 0x26, 0xCB, 0x66, 0xA7, 0xC0, 0xD2, 0xAE, 0xB9, 0x58, 0xDB, 
  0xDA, 0x1C, 0x16, 0x0C, 0x10, 0xDF, 0xAB, 0x42, 0x42, 0xFF, 0xEE, 0xF8, 0xE7, 0x30, 0x9A, 0x76, 0x4C, 0xC6, 0x94, 0xC9, 
  0x98, 0x3F, 0x2F, 0x89, 0x68, 0x3B, 0xCE, 0xF9, 0xBB, 0x19, 0xFF, 0x87, 0x1C, 0x39, 0x05, 0xB4, 0x20, 0x0A, 0x11, 0xE2, 
  0x1E, 0xA3, 0x0A, 0x27, 0xC9, 0xC5, 0xC9, 0xAD, 0x7F, 0xFB, 0xD3, 0xC2, 0x52, 0x7F, 0x7F, 0x7D, 0xFB, 0x8A, 0x8E, 0xCE, 
  0x6E, 0xDB, 0x20, 0x05, 0x2A, 0x1F, 0xE3, 0x46, 0xB9, 0x82, 0xC6, 0xB4, 0x86, 0x60, 0x7E, 0x32, 0x1C, 0xC8, 0x8B, 0x56, 
  0x54, 0xAF, 0xD7, 0x47, 0x01, 0xFC, 0x04, 0x39, 0x8F, 0xBA, 0xFC, 0x84, 0x9D, 0x64, 0x87, 0x3D, 0x75, 0x41, 0x34, 0xA4, 
  0xD0, 0xDC, 0x39, 0x84, 0xF2, 0xE9, 0x83, 0xB9, 0x76, 0x38, 0x6B, 0xAC, 0x88, 0x91, 0x65, 0xE8, 0xB6, 0x56, 0xBD, 0x9C, 
  0xD7, 0x0B, 0xD7, 0x39, 0x82, 0x6B, 0x3B, 0x0A, 0xC0, 0x54, 0xE1, 0x36, 0xA7, 0xC1, 0x96, 0xC5, 0xA0, 0xC8, 0x33, 0x83, 
  0x79, 0x1C, 0xD9, 0xCE, 0xAA, 0x65, 0xCF, 0xAF, 0xF5, 0x04, 0x69, 0x87, 0xCB, 0x08, 0xA2, 0x82, 0x54, 0xD8, 0xDB, 0x09, 
  0xB5, 0xCB, 0x7E, 0x7E, 0x19, 0x87, 0x56, 0x6B, 0xC5, 0x61, 0x1E, 0xD7, 0x8C, 0xB7, 0x4D, 0x71, 0x00, 0x75, 0xFB, 0xDF, 
  0x85, 0x0A, 0xAD, 0xDE, 0x2A, 0x46, 0xDD, 0xE3, 0xC5, 0xBC, 0xE9, 0x34, 0x86, 0xD1, 0x18, 0x6A, 0x6A, 0x00, 0xBD, 0xFB, 
  0x1D, 0xAA, 0xD6, 0x31, 0x0C, 0x5D, 0xE5, 0x85, 0x78, 0x06, 0x41, 0xC0, 0xB1, 0x4A, 0xF8, 0x2D, 0x61, 0x75, 0x19, 0x3A, 
  0xA9, 0x2C, 0x25, 0x28, 0x4A, 0x67, 0x8A, 0x2E, 0xB4, 0x5B, 0x5A, 0xD9, 0x9C, 0x6E, 0x2E, 0x6A, 0x5B, 0xED, 0xCB, 0xF0, 
  0x9B, 0x82, 0xC0, 0x5C, 0xEB, 0xA9, 0x47, 0xA9, 0x9C, 0xB5, 0xD0, 0xD9, 0x45, 0x43, 0x10, 0x36, 0xFC, 0xE0, 0x3B, 0xF0, 
  0x85, 0x8A, 0x7B, 0x88, 0x46, 0x33, 0x08, 0xCA, 0x5E, 0xE3, 0x3F, 0xFB, 0xF1, 0x59, 0x9F, 0xD3, 0x12, 0x70, 0x2A, 0x03, 
  0xB9, 0x2A, 0xF2, 0xF6, 0x2E, 0x71, 0x70, 0x62, 0xE8, 0x2C, 0x03, 0xC9, 0xBD, 0xAE, 0x8A, 0xC7, 0xFF, 0xA1, 0x7B, 0x39, 
  0xAA, 0x07, 0xF5, 0xC1, 0x3A, 0x9D, 0x4A, 0x1E, 0x86, 0x2D, 0x59, 0xD8, 0x49, 0x6A, 0x33, 0x1E, 0x62, 0xF4, 0x4B, 0x64, 
  0x21, 0xE6, 0xB2, 0x4F, 0x7E, 0x4F, 0x5D, 0xD0, 0xC4, 0x6C, 0xEF, 0x15, 0x10, 0x74, 0x4E, 0x3D, 0x3D, 0x6A, 0xEC, 0x3B, 
  0xB1, 0x11, 0x9F, 0xFE, 0x79, 0xAB, 0xBC, 0xCF, 0xC8, 0xD3, 0x88, 0x46, 0x2D, 0xF8, 0xE5, 0xA9, 0x1A, 0x9B, 0x2B, 0x75, 
  0x49, 0x17, 0x94, 0xCC, 0x5B, 0xCE, 0x63, 0xAD, 0x72, 0x4B, 0x16, 0x53, 0xA1, 0xCB, 0x9E, 0x75, 0xA8, 0x5C, 0x87, 0x5B, 
  0x88, 0x5E, 0xC4, 0x90, 0xCC, 0x29, 0x6E, 0xF3, 0xBA, 0x30, 0xA3, 0xF5, 0x4C, 0xC5, 0x9E, 0x17, 0xED, 0x9D, 0xF7, 0xB1, 
  0x15, 0x84, 0x66, 0x17, 0x21, 0xA2, 0xA3, 0xE2, 0xFF, 0x37, 0x19, 0x85, 0x6A, 0xCC, 0xEC, 0x26, 0x3D, 0xA5, 0xC3, 0x6D, 
  0xC7, 0x92, 0xEF, 0xA2, 0xED, 0x1F, 0xC5, 0xA5, 0xD6, 0xEA, 0x13, 0x57, 0x78, 0xF2, 0xB9, 0x2A, 0x0F, 0x44, 0x16, 0x99, 
  0x6B, 0x1A, 0x7B, 0xD0, 0xCB, 0x7A, 0xA1, 0xAD, 0x89, 0x69, 0xE5, 0x6A, 0x6A, 0xCB, 0x45, 0xF3, 0xB6, 0x02, 0xA7, 0x12, 
  0x57, 0xF2, 0xE9, 0x3D, 0xB2, 0x51, 0xD9, 0x47, 0x39, 0xB0, 0xCA, 0x5D, 0x7F, 0xD0, 0x9F, 0xD8, 0xE3, 0xDA, 0x81, 0x2E, 
  0x9E, 0x6A, 0x6B, 0x2D, 0xA3, 0xB4, 0x57, 0xFB, 0x11, 0xA3, 0xA5, 0xFA, 0x0A, 0x88, 0x1B, 0xB2, 0x52, 0x36, 0xE6, 0xB2, 
  0x4D, 0x08, 0x8B, 0x4F, 0xF8, 0xFA, 0x3A, 0x6A, 0xF4, 0x66, 0x47, 0xC6, 0xC4, 0xD9, 0x5D, 0xEF, 0x91, 0x13, 0x10, 0x8D, 
  0x26, 0xCE, 0xD1, 0xFC, 0xCC, 0xC2, 0x37, 0x53, 0xEC, 0xAE, 0x7F, 0x17, 0x3E, 0x54, 0xA9, 0x41, 0x7C, 0x65, 0xF8, 0x99, 
  0xBE, 0x5B, 0xD6, 0xB7, 0xA1, 0x98, 0x8B, 0xA3, 0xF2, 0x84, 0xC1, 0x07, 0xF1, 0xF9, 0xF1, 0x57, 0x7D, 0xFB, 0x07, 0x9C, 
  0x72, 0x12, 0xD0, 0x44, 0xA3, 0x53, 0x73, 0xF0, 0x2B, 0x3D, 0x0C, 0xBD, 0xE3, 0xE2, 0xFD, 0xB3, 0x3D, 0x68, 0xA1, 0xC1, 
  0xE8, 0xBD, 0x0E, 0xFF, 0xB3, 0x3B, 0x1B, 0x42, 0xFC, 0xE1, 0xBA, 0xA4, 0x12, 0xC7, 0xAA, 0xEA, 0x29, 0x37, 0xBC, 0x53, 
  0x7F, 0x75, 0xB4, 0x2E, 0x59, 0x42, 0xE3, 0x31, 0x69, 0xFE, 0x5E, 0x77, 0x81, 0x37, 0x3B, 0xC5, 0xF7, 0xD0, 0x48, 0x5A, 
  0x9F, 0x8B, 0x76, 0x66, 0xBF, 0xF3, 0x7D, 0x7E, 0x06, 0x0A, 0xB9, 0x3B, 0x6A, 0x99, 0xDE, 0xC7, 0x38, 0x9A, 0x31, 0x81, 
  0xF5, 0x66, 0xE4, 0x27, 0xE8, 0x30, 0x5F, 0x76, 0x43, 0x1A, 0x58, 0xCB, 0xAC, 0xA3, 0x90, 0xBC, 0x72, 0x6A, 0x89, 0x8B, 
  0x64, 0xEE, 0xDE, 0x1C, 0x3F, 0xF3, 0xD9, 0xC9, 0x1A, 0xE3, 0xC5, 0x1E, 0x05, 0x3A, 0xE6, 0x19, 0x3C, 0xD9, 0x9F, 0x03, 
  0x9F, 0x67, 0x1B, 0xFB, 0x72, 0x19, 0x64, 0xA3, 0x8E, 0xB8, 0x37, 0xBD, 0xE0, 0x8F, 0xFE, 0x40, 0x75, 0x45, 0x89, 0x22, 
  0xB2, 0x79, 0x52, 0x66, 0xD6, 0xA9, 0x41, 0xE3, 0xA3, 0x2C, 0x32, 0xF8, 0x27, 0xAE, 0x6F, 0x3B, 0x87, 0x66, 0xF7, 0xC0, 
  0x52, 0x4E, 0x76, 0x76, 0x43, 0x09, 0xEC, 0xF9, 0x44, 0x31, 0xCD, 0x53, 0x67, 0x6C, 0x0A, 0xB5, 0xD7, 0xAE, 0xE1, 0x97, 
  0x29, 0xEF, 0x4E, 0x25, 0xE3, 0xE8, 0xF4, 0x2F, 0x58, 0x04, 0xA6, 0x6E, 0x6D, 0x31, 0xF8, 0xBF, 0x7C, 0x37, 0xFB, 0x03, 
  0xFB, 0x4E, 0x99, 0xE9, 0x4F, 0x01, 0x13, 0x25, 0xF9, 0x1F, 0x78, 0xC2, 0x9F, 0x28, 0xB1, 0x44, 0x3A, 0xB1, 0xE0, 0x1E, 
  0x30, 0x29, 0xAA, 0xD3, 0x29, 0x2F, 0xE0, 0xFD, 0xC3, 0xE4, 0x0E, 0x28, 0x74, 0x27, 0x1A, 0x94, 0x55, 0xBB, 0xD8, 0x34, 
  0xE2, 0x41, 0x8C, 0x4E, 0xD2, 0xC3, 0xA6, 0xE0, 0x28, 0x9B, 0x39, 0x03, 0x85, 0x9C, 0x97, 0x77, 0x6F, 0x6C, 0xA8, 0x0E, 
  0x1A, 0x60, 0x12, 0xAD, 0x49, 0xF8, 0xE0, 0xD7, 0x3B, 0x55, 0x37, 0xD1, 0x79, 0x45, 0xF1, 0xA2, 0xF7, 0xDE, 0x04, 0x68, 
  0xBF, 0x2A, 0x39, 0xC8, 0x67, 0x2B, 0xB6, 0x54, 0xFA, 0x02, 0xE3, 0x7A, 0x5F, 0x1B, 0x08, 0xB9, 0x6F, 0x0A, 0xBC, 0x4D, 
  0x96, 0xC4, 0xF1, 0x6A, 0xC4, 0xFB, 0x42, 0x53, 0xBA, 0xEC, 0xB1, 0x4C, 0xF1, 0x29, 0xA6, 0x93, 0xE0, 0xF9, 0x2C, 0xB0, 
  0x32, 0x02, 0x94, 0x98, 0xA6, 0xEA, 0x5C, 0x3B, 0xC0, 0x59, 0x2E, 0x53, 0x00, 0x15, 0xD5, 0x5D, 0x38, 0x08, 0xCC, 0x19, 
  0x63, 0x48, 0x6C, 0x77, 0xBA, 0x9D, 0x42, 0x50, 0x6A, 0x10, 0x4B, 0xE2, 0x4B, 0xC5, 0xAC, 0x92, 0x63, 0xC4, 0xF7, 0x98, 
  0xD2, 0x7A, 0x13, 0xDB, 0x9E, 0xFA, 0xA8, 0xA1, 0x67, 0x99, 0x85, 0x12, 0xD1, 0x5E, 0xBB, 0xA6, 0x04, 0xF1, 0xAB, 0x25, 
  0x8A, 0xAB, 0xDA, 0xF2, 0xBE, 0xC0, 0x41, 0x64, 0x07, 0x6A, 0xA4, 0xB9, 0xE2, 0x31, 0xF1, 0x97, 0xA2, 0x45, 0xFC, 0x8D, 
  0xC5, 0x6A, 0x2A, 0x66, 0xD7, 0x9E, 0xD0, 0x18, 0xE9, 0xD5, 0x3D, 0x8F, 0x23, 0xA2, 0xBB, 0x85, 0xB9, 0x0D, 0xFE, 0x24, 
  0xD3, 0xE6, 0xC7, 0x2B, 0x69, 0x4A, 0x4E, 0xBF, 0xBF, 0xA4, 0x9A, 0x8E, 0xFD, 0x1F, 0xF9, 0x6F, 0x58, 0x1A, 0x2C, 0xF3, 
  0x11, 0xBA, 0x19, 0x4F, 0x85, 0x2A, 0x86, 0x03, 0x1A, 0x8D, 0xA3, 0xB7, 0x3C, 0xB4, 0xF0, 0x63, 0xC9, 0xCC, 0x85, 0xBA, 
  0xEA, 0x16, 0x88, 0x4B, 0x5B, 0x7C, 0xA0, 0x54, 0x88, 0x38, 0xC4, 0x6A, 0xCD, 0x0C, 0xC0, 0x28, 0x8C, 0x56, 0x70, 0xF8, 
  0x35, 0xE2, 0x4F, 0x4A, 0x94, 0xF5, 0xF5, 0x64, 0x30, 0x41, 0xCA, 0x4B, 0x60, 0x70, 0x29, 0x8B, 0x4E, 0xAB, 0x2D, 0x36, 
  0x1C, 0xEF, 0xB6, 0xD0, 0xFB, 0xE9, 0x26, 0x12, 0x09, 0xE2, 0xCE, 0x5C, 0x6E, 0x79, 0xF6, 0x16, 0x3C, 0x00, 0xC4, 0xA3, 
  0x6D, 0x2B, 0xB0, 0xD0, 0x24, 0xAC, 0xCC, 0xB4, 0x00, 0x38, 0x78, 0x76, 0xD2, 0x68, 0x75, 0xD1, 0x65, 0x7E, 0x85, 0xFB, 
  0x6D, 0x93, 0x9A, 0xA8, 0x0A, 0xEA, 0x34, 0xA8, 0xEB, 0x48, 0x1B, 0x86, 0x6F, 0x41, 0xF5, 0x70, 0x33, 0xEE, 0x01, 0xEF, 
  0x91, 0xCD, 0xD2, 0xFC, 0xE5, 0xD3, 0x04, 0xA5, 0xF5, 0xA1, 0xDD, 0xEA, 0xFD, 0xC7, 0x0C, 0x93, 0xC3, 0x8B, 0xA5, 0x1E, 
  0xD0, 0x25, 0x8E, 0x43, 0xC9, 0x05, 0xE9, 0x18, 0x91, 0xC9, 0x07, 0xA7, 0x37, 0xC6, 0x95, 0x72, 0x9D, 0x54, 0x83, 0xB7, 
  0x23, 0x86, 0x68, 0x70, 0x91, 0x9A, 0x66, 0xB8, 0xA5, 0x9D, 0x1D, 0x10, 0xDD, 0x12, 0x0D, 0xB6, 0xB0, 0x85, 0xB6, 0xDE, 
  0x30, 0xAE, 0xCC, 0x7D, 0xB7, 0xE3, 0xF0, 0xDB, 0x2C, 0x82, 0xBF, 0xB9, 0x1B, 0xB3, 0xF6, 0xD5, 0xF6, 0x5C, 0x7B, 0x67, 
  0x7A, 0x49, 0xB5, 0x14, 0x55, 0x0D, 0x3A, 0xF2, 0x72, 0xEE, 0x22, 0x5B, 0x39, 0xC2, 0xAD, 0x75, 0xDE, 0x87, 0x44, 0x74, 
  0xF5, 0x73, 0x54, 0xC2, 0x0D, 0x98, 0x68, 0xCB, 0x39, 0xD2, 0xA3, 0x19, 0xE7, 0xAC, 0x46, 0x64, 0x32, 0x6B, 0x44, 0x96, 
  0xB6, 0x18, 0x42, 0x32, 0x44, 0x3C, 0x21, 0xD8, 0x5E, 0x2D, 0xF7, 0xF9, 0xCC, 0x38, 0x41, 0xE6, 0x31, 0xBE, 0x09, 0x0D, 
  0x9D, 0x5C, 0x1B, 0x85, 0xBF, 0x31, 0x30, 0x8E, 0x59, 0x51, 0x97, 0xB5, 0xE4, 0xE3, 0x3F, 0x2E, 0x7B, 0xA8, 0x1C, 0x5E, 
  0x6A, 0x8F, 0xC8, 0x72, 0xCC, 0x57, 0xE4, 0x8A, 0xEC, 0x95, 0xF9, 0x5B, 0xA3, 0xF8, 0xF3, 0x9F, 0xB4, 0xDB, 0x6C, 0x4B, 
  0xD7, 0x7D, 0xFC, 0x93, 0x70, 0x5B, 0x2A, 0xB8, 0x81, 0xEB, 0x14, 0x62, 0xA3, 0xBA, 0x6A, 0xB2, 0x40, 0xC6, 0x70, 0xF6, 
  0xC7, 0x27, 0x21, 0xCF, 0x11, 0x78, 0x42, 0x44, 0x91, 0x81, 0x66, 0x32, 0x0B, 0x8D, 0xDA, 0x6A, 0x2D, 0x87, 0xCF, 0xC9, 
  0x90, 0xF8, 0xB8, 0x0F, 0x69, 0x9B, 0xFF, 0x34, 0xFF, 0xC1, 0x59, 0x5F, 0xD6, 0xCE, 0xC1, 0x77, 0x01, 0x76, 0x68, 0x7D, 
  0xCB, 0x05, 0x4C, 0x7D, 0x0B, 0x2D, 0x2A, 0xCF, 0x2A, 0x3F, 0x97, 0x35, 0x74, 0xF6, 0xC1, 0x37, 0xE4, 0xE0, 0x1C, 0x20, 
  0x75, 0xDA, 0xA7, 0xF6, 0x46, 0xEF, 0xBB, 0x24, 0x81, 0x9B, 0x32, 0x0E, 0x14, 0x32, 0x16, 0x9B, 0x87, 0x80, 0x68, 0x31, 
  0x2B, 0x86, 0xB5, 0x2B, 0xC4, 0xD5, 0x59, 0xAE, 0xF7, 0xEB, 0x79, 0xFE, 0xE8, 0x26, 0x81, 0x32, 0x2C, 0x43, 0x34, 0x97, 
  0x66, 0x66, 0x2D, 0x13, 0x33, 0x7F, 0xAC, 0x58, 0x5F, 0x5A, 0x52, 0xAE, 0x0C, 0x4A, 0xA2, 0xAB, 0x40, 0x98, 0x18, 0xDD, 
  0x09, 0x36, 0x9D, 0x6F, 0x47, 0xDA, 0x6A, 0x13, 0x14, 0xE7, 0x9C, 0xDC, 0xF7, 0x33, 0x5D, 0xFB, 0xB4, 0x8A, 0x43, 0x4E, 
  0xA9, 0x23, 0xDB, 0xA5, 0xDB, 0xC2, 0x18, 0xC6, 0xA3, 0x90, 0xBB, 0xDB, 0x7F, 0x25, 0xFB, 0xC7, 0xFA, 0xE3, 0x58, 0xB0, 
  0xF0, 0x0F, 0x0E, 0x90, 0x3C, 0x8B, 0x31, 0x3B, 0xDE, 0xA1, 0x77, 0xE5, 0x33, 0xAD, 0xE4, 0x89, 0x74, 0x47, 0xBE, 0x1B, 
  0xCA, 0x4E, 0xC8, 0xE0, 0x36, 0x5D, 0x8C, 0x0B, 0x2E, 0xEC, 0x8E, 0x66, 0x7F, 0x61, 0x41, 0x76, 0xA1, 0xC6, 0x94, 0x3C, 
  0xF4, 0x52, 0x27, 0x25, 0xC0, 0x9D, 0x2E, 0x39, 0x9B, 0x5D, 0x5A, 0x60, 0xD0, 0xF7, 0x42, 0x62, 0x45, 0x34, 0x22, 0xBA, 
  0xDC, 0x43, 0xF2, 0x1A, 0xCE, 0xBE, 0x28, 0x0C, 0x6E, 0x58, 0xEE, 0xA3, 0xBD, 0xEB, 0x76, 0x9C, 0x25, 0x3C, 0x7B, 0x1E, 
  0x77, 0x06, 0x6D, 0xCC, 0x3F, 0xCC, 0xAD, 0x44, 0x96, 0xC9, 0x27, 0x92, 0x8B, 0x69, 0xCB, 0x3F, 0x7E, 0x7E, 0x25, 0xC6, 
  0x95, 0x4A, 0x37, 0x14, 0x9E, 0x43, 0xDB, 0x96, 0x1C, 0x43, 0xA9, 0xC8, 0xAD, 0xEF, 0xF8, 0x5E, 0x42, 0x41, 0xDA, 0x40, 
  0xAA, 0xD9, 0x11, 0x87, 0x4C, 0xAB, 0xCC, 0x30, 0x4B, 0x8E, 0xBD, 0x6B, 0x38, 0x1F, 0xF0, 0xD0, 0xB9, 0xF3, 0x4E, 0xFA, 
  0x9A, 0x32, 0xE6, 0xCC, 0xC2, 0x38, 0xF7, 0x10, 0x10, 0xE2, 0x8B, 0x48, 0xD5, 0x7B, 0x67, 0x9A, 0x4E, 0x6C, 0xB8, 0x8B
]

sbox = [
    0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41,
    0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD,
    0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A,
    0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D,
    0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99, 
    0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7,
    0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18, 0xF2, 0x22,
    0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50,
    0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
    0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03, 0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94, 
    0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
    0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E,
    0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E, 0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59,
    0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA,
    0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4, 
    0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77, 0xC7, 0x80, 0x9E
]

brick_map = [
    '..................',
    '..................',
    '..................',
    '..................',
    '..................',
    '..................',
    '.....#......#.....',
    '......#....#......',
    '.....########.....',
    '....##.####.##....',
    '...############...',
    '...#.########.#...',
    '...#.#......#.#...',
    '......##..##......',
    '..................',
    '..................',
    '..................',
    '..................',
    '..................',
    '..................'
]


# ----------------------------------------------------------------------------------------
# Helper routines for cracking.
to_str = lambda A: '-'.join('%02X' % a for a in A)

int_to_beta_key_to = lambda n: \
    ''.join('0123456789ABCDEFGHJKLMNPRTUVWXYZ'[(n >> a) & 0x1F] for a in range(0, 60, 5))

def beta_key_to_int(key):
    n = 0
    for i in key[::-1]:
        n = (n << 5) | '0123456789ABCDEFGHJKLMNPRTUVWXYZ'.index(i)
    return n

qword_to_list = lambda q: [(q >> i) & 0xFF for i in range(0, 64, 8)]  # little endian.


# ----------------------------------------------------------------------------------------
def galois_encryption(beta_key_int, rnd_seed, verbose=False):
    """Custom encryption using Galois Fields."""
    if verbose: print(f'[+] Encrypting beta key value: {beta_key_int:016X}')

    # Generate random map.
    # For `rnd_seed` = 'Beta Key' the expected value for `rnd_map is:
    #
    #    2A 0D 1C 09 48 23 0D 11 74 3A 18 32 B0 66 3A 02
    #    C8 54 10 44 41 EC 54 24 C9 F0 78 D0 DA 81 F0 10
    #    12 60 71 20 34 82 60 A1 E4 00 22 80 A8 C5 00 83
    #    0C C5 81 C4 94 4E C5 C2 1B 88 00 8A 2A 9F 88 86
    #    24 05 16 01 42 2B 05 19 58 1A 3C 12 94 46 1A 22
    #    B4 30 6C 40 3D 98 30 60
    rnd_map = []
    for i, a in enumerate('hxp{certainlynotaflag}'[:11]):
        for b in rnd_seed[:8]:
            rnd_map.append(((((ord(b) ^ ord(a)) + (i >> 3)) >> (8 - (i & 7))) | 
                            (((ord(b) ^ ord(a)) + (i >> 3)) << (i & 7))) & 0xFF)

    if verbose: print(f'[+] Random map: {to_str(rnd_map)}')

    beta_key = beta_key_int.to_bytes(8, 'little')
    if verbose: print(f'[+] Beta key as list: {to_str(beta_key)}')

    beta_key = [b ^ r ^ 0x11 for b, r in zip(beta_key, rnd_map)]
    if verbose: print(f'[+] Beta key after XOR : {to_str(beta_key)}')


    # ----------------------------------------------------------------
    # Helper routines for Galois Fields.
    # ----------------------------------------------------------------
    #
    # Addition & multiplication in GF(2^8) using: x^8 + x^4 + x^3 + x^2 + 1.
    def GFadd(a, b): return a ^ b
    def GFmul(a, b):
        p = 0
        while a != 0 and b != 0:
            if (b & 1):
                p ^= a;

            if a & 0x80:
                a = (a << 1) ^ 0x11D
            else:
                a <<= 1 
            b >>= 1
        
        return p
  
    GFop = lambda lo, c1, c2, c3, c4: \
            GFmul(lo[0], c1) ^ GFmul(lo[1], c2) ^ GFmul(lo[2], c3) ^ GFmul(lo[3], c4)


    for i in range(2, 0xB+1):  # Repeat for 10 rounds.
        beta_key = [sbox[b] for b in beta_key]
        if verbose: print(f'[+]    Beta key after SBOX: {to_str(beta_key)}')

        lo, hi = beta_key[:4], beta_key[4:]

        lo_nxt = [
            GFop(lo, 0b001, 0b011, 0b100, 0b101) ^ GFop(hi, 0b0110, 0b1000, 0b1011, 0b0111),
            GFop(lo, 0b011, 0b001, 0b101, 0b100) ^ GFop(hi, 0b1000, 0b0110, 0b0111, 0b1011),
            GFop(lo, 0b100, 0b101, 0b001, 0b011) ^ GFop(hi, 0b1011, 0b0111, 0b0110, 0b1000),
            GFop(lo, 0b101, 0b100, 0b011, 0b001) ^ GFop(hi, 0b0111, 0b1011, 0b1000, 0b0110),
        ]

        hi_nxt = [
            GFop(lo, 6, 8, 11, 7)                    ^ GFop(hi, 1, 3, 4, 5),
            GFop(lo, 0b1000, 0b0110, 0b0111, 0b1011) ^ GFop(hi, 0b011, 0b001, 0b101, 0b100),
            GFop(lo, 0b1011, 0b0111, 0b0110, 0b1000) ^ GFop(hi, 0b100, 0b101, 0b001, 0b011),
            GFop(lo, 0b0111, 0b1011, 0b1000, 0b0110) ^ GFop(hi, 0b101, 0b100, 0b011, 0b001),
        ]

        '''
        # ~~~~~ OLDER (NOT SIMPLIFIED) VERSION OF THE CODE ~~~~~

        # Galois Fields helper routines (K rounds of multiplication).
        galois_1_round = lambda lo: \
            [((a << 1) ^ 0x1D if a & 0x80 else a << 1) & 0xFF for a in lo]

        galois_2_rounds = lambda lo: \
            galois_1_round(galois_1_round(lo))

        galois_3_rounds = lambda lo: \
            galois_1_round(galois_1_round(galois_1_round(lo)))

        A = galois_1_round(lo)   # lo*2 
        B = galois_1_round(hi)   # hi*2
        C = galois_2_rounds(lo)  # lo*4, or C = galois_1_round(A)
        D = galois_2_rounds(hi)  # hi*4, or D = galois_1_round(B)
        E = galois_3_rounds(lo)  # lo*8, or E = galois_1_round(C)
        F = galois_3_rounds(hi)  # hi*8, or F = galois_1_round(D)

        lo_nxt = [
            lo[0]^lo[1]^lo[3] ^ A[1] ^ B[0]^B[2]^B[3] ^ C[2]^C[3] ^ D[0]^D[3] ^ F[1]^F[2] ^ hi[2]^hi[3],
            lo[0]^lo[1]^lo[2] ^ A[0] ^ B[1]^B[2]^B[3] ^ C[2]^C[3] ^ D[1]^D[2] ^ F[0]^F[3] ^ hi[2]^hi[3],
            lo[1]^lo[2]^lo[3] ^ A[3] ^ B[0]^B[1]^B[2] ^ C[0]^C[1] ^ D[1]^D[2] ^ F[0]^F[3] ^ hi[0]^hi[1],
            lo[0]^lo[2]^lo[3] ^ A[2] ^ B[0]^B[1]^B[3] ^ C[0]^C[1] ^ D[0]^D[3] ^ F[1]^F[2] ^ hi[0]^hi[1],
        ]

        # Exactly the same as lo_nxt with substitutions:
        #       lo ~> hi, hi ~> lo, A ~> B, B ~> A, C ~> D, D ~> C, E ~> F, F ~> E
        hi_nxt = [
            lo[2]^lo[3] ^ A[0]^A[2]^A[3] ^ B[1] ^ C[0]^C[3] ^ D[2]^D[3] ^ E[1]^E[2] ^ hi[0]^hi[1]^hi[3],
            lo[2]^lo[3] ^ A[1]^A[2]^A[3] ^ B[0] ^ C[1]^C[2] ^ D[2]^D[3] ^ E[0]^E[3] ^ hi[0]^hi[1]^hi[2],
            lo[0]^lo[1] ^ A[0]^A[1]^A[2] ^ B[3] ^ C[1]^C[2] ^ D[0]^D[1] ^ E[0]^E[3] ^ hi[1]^hi[2]^hi[3],
            lo[0]^lo[1] ^ A[0]^A[1]^A[3] ^ B[2] ^ C[0]^C[3] ^ D[0]^D[1] ^ E[1]^E[2] ^ hi[0]^hi[2]^hi[3],
        ]
        '''

        if verbose: print(f'[+] Round {i:2d}: Beta Key: '
                          f'LO={to_str(lo)}, HI={to_str(hi)} ~> '
                          f'LO={to_str(lo_nxt)}, HI={to_str(hi_nxt)}')


        # Combine low and high keys to derive the new beta key.
        beta_key = lo_nxt + hi_nxt
        beta_key = [b ^ r ^ 0x11*i for b, r in zip(beta_key, rnd_map[8:])]

        if verbose: print(f'[+]    Beta key after XOR : {to_str(beta_key)}')

        rnd_map = rnd_map[8:]  # Move on the next 8 bytes of random map.

    if verbose: print(f'[+] Final ciphertext: {to_str(beta_key)}')

    return beta_key


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] hxp3drm crack started.')

    # ----------------------------------------------------------------
    # Testing encryption (not needed for cracking).
    # ----------------------------------------------------------------
    # i) Encrypt a random beta key:
    beta_key = '1ZY00000010Z'
    cipher1 = galois_encryption(beta_key_to_int(beta_key), 'Beta Key', True)
    print(f'[+] Galois_Fields_Encryption({beta_key}) = {to_str(cipher1)}')

    # ii) Encrypt the correct beta key:
    beta_key = 'PL5L3TM31NKK'
    cipher2 = galois_encryption(beta_key_to_int(beta_key), 'Beta Key')
    print(f'[+] Galois_Fields_Encryption({beta_key}) = {to_str(cipher2)}')

    # iii) Encrypt coordinates of the first brick that gets hit:
    cipher3 = galois_encryption(0x0707, 'Play well, get flag.'[11:])
    print(f'[+] Galois_Fields_Encryption(0x0707) = {to_str(cipher3)}')


    # ----------------------------------------------------------------
    # Cracking starts from here.
    # ----------------------------------------------------------------
    beta_key_int = beta_key_to_int('PL5L3TM31NKK')
    beta_key_val = qword_to_list(beta_key_int)

    print(f'[+] Beta Key Int: 0x{beta_key_int:016X}')
    print(f'[+] Beta Key Val: {to_str(beta_key_val)}')

    # Compute score cipher from the coordinates of all bricks.
    score_cipher = [0]*8
    c = 1

    for y, row in enumerate(brick_map[::-1]):
        for x, cell in enumerate(row):
            if cell != '#': continue

            coords = (x << 8) | (y + 1)
            brick_cipher = galois_encryption(coords, 'Play well, get flag.'[11:])

            print(f'[+] {c:2d}: Galois_Fields_Encryption(0x{coords:04x}) ~> '
                  f'{to_str(brick_cipher)}  ({x:2d}, {y+1:2d})')

            # XOR all brick coordinates together.
            score_cipher = [s ^ b for s, b in zip(score_cipher, brick_cipher)]

            c += 1

    print(f'[+] Final score cipher from all bricks: {to_str(score_cipher)}')

    # Do MD5 and compute final decryption key.
    code_segm = list(open('code.segm', 'rb').read())
    md5 = hashlib.md5(bytes(code_segm))

    print(f'[+] MD5 of CODE segment: {md5.hexdigest()}')

    digest = [d for d in md5.digest()]
    aes_key = [0]*16
    for i in range(8):
        aes_key[i]   = digest[i]   ^ beta_key_val[i]
        aes_key[i+8] = digest[i+8] ^ score_cipher[i]

    print(f'[+] Final AES key: {to_str(aes_key)}')

    # Decrypt ciphertext with ASCII art flag.
    print('[+] ASCII art flag:')
    crypto = AES.new(key=bytes(aes_key), IV=('\0'*16).encode('utf-8'), mode=AES.MODE_CBC)
    plain = crypto.decrypt(bytes(flag_ASCII_ciphertext))

    # Plaintext is 2560 ~ 2556 = 142 (flag parts) * 18 (rows) bytes.
    for i in range(0, len(plain), 142):       
        print(f'[+] {plain[i:i+142]}')


    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/hxp_2021/hxp3drm$ time ./hxp3drm_crack.py
[+] hxp3drm crack started.
[+] Encrypting beta key value: 0F80200000007BE1
[+] Random map: 2A-0D-1C-09-48-23-0D-11-74-3A-18-32-B0-66-3A-02-C8-54-10-44-41-EC-54-24-C9-F0-78-D0-DA-81-F0-10-12-60-71-20-34-82-60-A1-E4-00-22-80-A8-C5-00-83-0C-C5-81-C4-94-4E-C5-C2-1B-88-00-8A-2A-9F-88-86-24-05-16-01-42-2B-05-19-58-1A-3C-12-94-46-1A-22-B4-30-6C-40-3D-98-30-60
[+] Beta key as list: E1-7B-00-00-00-20-80-0F
[+] Beta key after XOR : DA-67-0D-18-59-12-9C-0F
[+]    Beta key after SBOX: AB-1C-0C-ED-B7-6B-09-41
[+] Round  2: Beta Key: LO=AB-1C-0C-ED, HI=B7-6B-09-41 ~> LO=A2-2B-C1-87, HI=86-D7-60-3C
[+]    Beta key after XOR : F4-33-FB-97-14-93-78-1C
[+]    Beta key after SBOX: BB-CA-F4-DB-45-48-24-1D
[+] Round  3: Beta Key: LO=BB-CA-F4-DB, HI=45-48-24-1D ~> LO=64-DE-9F-AF, HI=0E-60-C6-48
[+]    Beta key after XOR : 9F-B9-BC-D8-7C-BF-A1-5F
[+]    Beta key after SBOX: 94-96-13-D4-60-2E-5C-D7
[+] Round  4: Beta Key: LO=94-96-13-D4, HI=60-2E-5C-D7 ~> LO=CD-C7-82-4D, HI=F3-B5-07-84
[+]    Beta key after XOR : 40-73-BE-D9-6D-70-B3-D0
[+]    Beta key after SBOX: 8B-B2-63-25-18-FE-26-78
[+] Round  5: Beta Key: LO=8B-B2-63-25, HI=18-FE-26-78 ~> LO=A1-37-41-3B, HI=9F-5C-18-F0
[+]    Beta key after XOR : E6-02-65-4E-FE-8B-2D-04
[+]    Beta key after SBOX: AC-2C-1B-84-80-95-C5-B3
[+] Round  6: Beta Key: LO=AC-2C-1B-84, HI=80-95-C5-B3 ~> LO=EB-ED-EC-0D, HI=A8-6D-E6-B8
[+]    Beta key after XOR : 69-8B-A8-EB-66-CE-80-5D
[+]    Beta key after SBOX: 0F-95-73-68-11-B4-AA-17
[+] Round  7: Beta Key: LO=0F-95-73-68, HI=11-B4-AA-17 ~> LO=B9-7C-FF-94, HI=D8-59-7C-CA
[+]    Beta key after XOR : C2-CE-09-27-3B-60-CE-7F
[+]    Beta key after SBOX: A7-B4-85-CE-D6-14-B4-50
[+] Round  8: Beta Key: LO=A7-B4-85-CE, HI=D6-14-B4-50 ~> LO=52-13-E2-07, HI=AF-73-F6-F0
[+]    Beta key after XOR : C1-13-6A-05-0D-64-F6-FE
[+]    Beta key after SBOX: 79-93-9C-27-0C-DE-43-80
[+] Round  9: Beta Key: LO=79-93-9C-27, HI=0C-DE-43-80 ~> LO=F6-F1-5E-88, HI=E7-BF-9F-56
[+]    Beta key after XOR : 4B-6D-D1-10-3C-0D-03-D6
[+]    Beta key after SBOX: 20-18-98-23-51-0C-EC-71
[+] Round 10: Beta Key: LO=20-18-98-23, HI=51-0C-EC-71 ~> LO=36-2E-9D-80, HI=92-9F-5D-16
[+]    Beta key after XOR : C4-9E-0B-38-AC-73-ED-9E
[+]    Beta key after SBOX: 9F-DD-35-D9-9D-B2-38-DD
[+] Round 11: Beta Key: LO=9F-DD-35-D9, HI=9D-B2-38-DD ~> LO=87-A0-A2-E3, HI=24-80-6D-CB
[+]    Beta key after XOR : 88-2B-75-18-A2-A3-E6-10
[+] Final ciphertext: 88-2B-75-18-A2-A3-E6-10
[+] Galois_Fields_Encryption(1ZY00000010Z) = 88-2B-75-18-A2-A3-E6-10
[+] Galois_Fields_Encryption(PL5L3TM31NKK) = 6F-A4-57-55-A7-66-14-A1
[+] Galois_Fields_Encryption(0x0707) = 7D-BF-C3-2A-8B-27-EA-C9
[+] Beta Key Int: 0x09CEC11D723A1697
[+] Beta Key Val: 97-16-3A-72-1D-C1-CE-09
[+]  1: Galois_Fields_Encryption(0x0607) ~> 1D-B7-FD-77-6B-83-79-50  ( 6,  7)
[+]  2: Galois_Fields_Encryption(0x0707) ~> 7D-BF-C3-2A-8B-27-EA-C9  ( 7,  7)
[+]  3: Galois_Fields_Encryption(0x0a07) ~> CF-7E-4D-CC-74-75-63-68  (10,  7)
[+]  4: Galois_Fields_Encryption(0x0b07) ~> D0-2D-C7-10-2A-9A-20-EF  (11,  7)
[+]  5: Galois_Fields_Encryption(0x0308) ~> 9F-CB-6E-99-EE-82-82-C0  ( 3,  8)
[+]  6: Galois_Fields_Encryption(0x0508) ~> 64-9C-80-E4-97-8A-B5-0D  ( 5,  8)
[+]  7: Galois_Fields_Encryption(0x0c08) ~> 6D-5D-51-01-F8-70-07-7A  (12,  8)
[+]  8: Galois_Fields_Encryption(0x0e08) ~> D8-BC-98-0A-A3-E8-28-41  (14,  8)
[+]  9: Galois_Fields_Encryption(0x0309) ~> D9-30-80-B6-70-24-C9-F7  ( 3,  9)
[+] 10: Galois_Fields_Encryption(0x0509) ~> 15-B3-39-83-EF-3A-D9-7E  ( 5,  9)
[+] 11: Galois_Fields_Encryption(0x0609) ~> F9-1C-E2-0A-88-69-8C-F4  ( 6,  9)
[+] 12: Galois_Fields_Encryption(0x0709) ~> 31-09-2E-B3-35-C9-B1-A7  ( 7,  9)
[+] 13: Galois_Fields_Encryption(0x0809) ~> 75-AD-39-3C-88-4A-AC-F2  ( 8,  9)
[+] 14: Galois_Fields_Encryption(0x0909) ~> 5A-8D-B7-6B-83-93-D1-D2  ( 9,  9)
[+] 15: Galois_Fields_Encryption(0x0a09) ~> 66-E4-63-CA-36-60-90-B9  (10,  9)
[+] 16: Galois_Fields_Encryption(0x0b09) ~> E1-1E-C1-A9-38-18-95-E5  (11,  9)
[+] 17: Galois_Fields_Encryption(0x0c09) ~> A2-D6-93-EF-AA-34-85-E5  (12,  9)
[+] 18: Galois_Fields_Encryption(0x0e09) ~> BC-A3-9C-49-6F-D5-19-D7  (14,  9)
[+] 19: Galois_Fields_Encryption(0x030a) ~> BF-50-7F-CE-59-DE-4F-8F  ( 3, 10)
[+] 20: Galois_Fields_Encryption(0x040a) ~> B3-3E-84-2F-14-1E-20-39  ( 4, 10)
[+] 21: Galois_Fields_Encryption(0x050a) ~> CC-80-1C-62-D6-31-8C-18  ( 5, 10)
[+] 22: Galois_Fields_Encryption(0x060a) ~> CA-7D-5A-A0-6A-99-34-A9  ( 6, 10)
[+] 23: Galois_Fields_Encryption(0x070a) ~> 9F-FF-F4-DC-17-8B-33-3D  ( 7, 10)
[+] 24: Galois_Fields_Encryption(0x080a) ~> CF-A5-82-D3-1B-F0-90-55  ( 8, 10)
[+] 25: Galois_Fields_Encryption(0x090a) ~> E9-84-AA-57-2C-6D-B0-84  ( 9, 10)
[+] 26: Galois_Fields_Encryption(0x0a0a) ~> CB-6A-69-05-6A-1D-C7-FB  (10, 10)
[+] 27: Galois_Fields_Encryption(0x0b0a) ~> 02-B0-95-3F-E1-9A-43-54  (11, 10)
[+] 28: Galois_Fields_Encryption(0x0c0a) ~> E2-CC-46-AB-E1-2B-07-8D  (12, 10)
[+] 29: Galois_Fields_Encryption(0x0d0a) ~> B9-40-D9-29-C9-36-2A-53  (13, 10)
[+] 30: Galois_Fields_Encryption(0x0e0a) ~> 69-5A-08-28-4D-2A-4F-27  (14, 10)
[+] 31: Galois_Fields_Encryption(0x040b) ~> 40-51-79-8E-BC-FC-1A-F1  ( 4, 11)
[+] 32: Galois_Fields_Encryption(0x050b) ~> 46-29-07-3C-7D-E9-A6-28  ( 5, 11)
[+] 33: Galois_Fields_Encryption(0x070b) ~> 9C-9D-D6-A9-DE-E7-35-E6  ( 7, 11)
[+] 34: Galois_Fields_Encryption(0x080b) ~> 1F-2F-96-8A-49-7B-C8-C4  ( 8, 11)
[+] 35: Galois_Fields_Encryption(0x090b) ~> EE-C0-35-A5-1D-92-CA-F3  ( 9, 11)
[+] 36: Galois_Fields_Encryption(0x0a0b) ~> DA-17-1F-2E-1D-35-5D-D9  (10, 11)
[+] 37: Galois_Fields_Encryption(0x0c0b) ~> 0E-B6-98-C9-08-5B-83-60  (12, 11)
[+] 38: Galois_Fields_Encryption(0x0d0b) ~> BC-80-28-16-4E-17-46-A1  (13, 11)
[+] 39: Galois_Fields_Encryption(0x050c) ~> 23-76-04-4D-29-65-72-0C  ( 5, 12)
[+] 40: Galois_Fields_Encryption(0x060c) ~> AE-04-DA-D1-93-A6-9F-BB  ( 6, 12)
[+] 41: Galois_Fields_Encryption(0x070c) ~> 26-F7-79-18-21-1D-28-36  ( 7, 12)
[+] 42: Galois_Fields_Encryption(0x080c) ~> E5-6E-CF-F4-31-AF-0D-A6  ( 8, 12)
[+] 43: Galois_Fields_Encryption(0x090c) ~> FA-67-E4-09-86-6F-5F-49  ( 9, 12)
[+] 44: Galois_Fields_Encryption(0x0a0c) ~> C4-93-6B-69-BD-D1-C1-9A  (10, 12)
[+] 45: Galois_Fields_Encryption(0x0b0c) ~> 13-89-C9-A5-20-22-CE-EF  (11, 12)
[+] 46: Galois_Fields_Encryption(0x0c0c) ~> 38-E6-40-34-95-71-E2-E3  (12, 12)
[+] 47: Galois_Fields_Encryption(0x060d) ~> E7-BD-CF-D8-99-95-70-DC  ( 6, 13)
[+] 48: Galois_Fields_Encryption(0x0b0d) ~> 3E-25-9A-F0-10-E0-80-DC  (11, 13)
[+] 49: Galois_Fields_Encryption(0x050e) ~> 3A-B4-6B-8B-B0-F7-44-7C  ( 5, 14)
[+] 50: Galois_Fields_Encryption(0x0c0e) ~> 96-C9-4A-E8-7A-E8-56-A3  (12, 14)
[+] Final score cipher from all bricks: E6-2B-71-0D-36-7F-A8-F6
[+] MD5 of CODE segment: 6003eb1327902438c4fefe49cd93a64a
[+] Final AES key: F7-15-D1-61-3A-51-EA-31-22-D5-8F-44-FB-EC-0E-BC
[+] ASCII art flag:
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                  ###               #####                 #               #####                               ###             '
[+] b'           #    # #    # #####   #    ##### #    # #     #          ####  #    #  #    # #     #          ####  #    # #    #    #            '
[+] b'           #    #  #  #  #    #  #      #   #    #       #         #    # #    #  ##  ##       #         #      #    #  #  #     #            '
[+] b'           ######   ##   #    # ##      #   ######  #####          #      #    #  # ## #  #####           ####  #    #   ##      ##           '
[+] b'           #    #   ##   #####   #      #   #    #       #         #  ### ####### #    #       #              # #    #   ##      #            '
[+] b'           #    #  #  #  #       #      #   #    # #     #         #    #      #  #    # #     #         #    # #    #  #  #     #            '
[+] b'           #    # #    # #        ###   #   #    #  #####           ####       #  #    #  #####           ####   ####  #    # ###             '
[+] b'                                                           #######                               #######                                      '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'                                                                                                                                              '
[+] b'    '
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------
