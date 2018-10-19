/*
Written by Peter O. in 2013.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal sealed class FastInteger2 {
    private sealed class MutableNumber {
      private int[] data;
      private int wordCount;

      internal MutableNumber(int val) {
        if (val < 0) {
          throw new ArgumentException("val (" + val + ") is less than " + "0 ");
        }
        this.data = new int[4];
        this.wordCount = (val == 0) ? 0 : 1;
        this.data[0] = val;
      }

      internal EInteger ToEInteger() {
        if (this.wordCount == 1 && (this.data[0] >> 31) == 0) {
          return (EInteger)((int)this.data[0]);
        }
        var bytes = new byte[(this.wordCount * 4) + 1];
        for (var i = 0; i < this.wordCount; ++i) {
          bytes[i * 4] = (byte)(this.data[i] & 0xff);
          bytes[(i * 4) + 1] = (byte)((this.data[i] >> 8) & 0xff);
          bytes[(i * 4) + 2] = (byte)((this.data[i] >> 16) & 0xff);
          bytes[(i * 4) + 3] = (byte)((this.data[i] >> 24) & 0xff);
        }
        bytes[bytes.Length - 1] = (byte)0;
        return EInteger.FromBytes(bytes, true);
      }

      internal int[] GetLastWordsInternal(int numWords32Bit) {
        var ret = new int[numWords32Bit];
        Array.Copy(this.data, ret, Math.Min(numWords32Bit, this.wordCount));
        return ret;
      }

      internal bool CanFitInInt32() {
        return this.wordCount == 0 || (this.wordCount == 1 && (this.data[0] >>
        31) == 0);
      }

      internal int ToInt32() {
        return this.wordCount == 0 ? 0 : this.data[0];
      }

      internal MutableNumber Multiply(int multiplicand) {
        if (multiplicand < 0) {
          throw new ArgumentException("multiplicand (" + multiplicand +
            ") is less than " + "0 ");
        }
        if (multiplicand != 0) {
          var carry = 0;
          if (this.wordCount == 0) {
            if (this.data.Length == 0) {
              this.data = new int[4];
            }
            this.data[0] = 0;
            this.wordCount = 1;
          }
          int result0, result1, result2, result3;
          if (multiplicand < 65536) {
            for (var i = 0; i < this.wordCount; ++i) {
              int x0 = this.data[i];
              int x1 = x0;
              int y0 = multiplicand;
              x0 &= 65535;
              x1 = (x1 >> 16) & 65535;
              int temp = unchecked(x0 * y0);  // a * c
              result1 = (temp >> 16) & 65535;
              result0 = temp & 65535;
              result2 = 0;
              temp = unchecked(x1 * y0);  // b * c
              result2 += (temp >> 16) & 65535;
              result1 += temp & 65535;
              result2 += (result1 >> 16) & 65535;
              result1 &= 65535;
              result3 = (result2 >> 16) & 65535;
              result2 &= 65535;
              // Add carry
              x0 = unchecked((int)(result0 | (result1 << 16)));
              x1 = unchecked((int)(result2 | (result3 << 16)));
              int x2 = unchecked(x0 + carry);
              if (((x2 >> 31) == (x0 >> 31)) ? ((x2 & Int32.MaxValue) < (x0 &
              Int32.MaxValue)) : ((x2 >> 31) == 0)) {
                // Carry in addition
                x1 = unchecked(x1 + 1);
              }
              this.data[i] = x2;
              carry = x1;
            }
          } else {
            for (var i = 0; i < this.wordCount; ++i) {
              int x0 = this.data[i];
              int x1 = x0;
              int y0 = multiplicand;
              int y1 = y0;
              x0 &= 65535;
              y0 &= 65535;
              x1 = (x1 >> 16) & 65535;
              y1 = (y1 >> 16) & 65535;
              int temp = unchecked(x0 * y0);  // a * c
              result1 = (temp >> 16) & 65535;
              result0 = temp & 65535;
              temp = unchecked(x0 * y1);  // a * d
              result2 = (temp >> 16) & 65535;
              result1 += temp & 65535;
              result2 += (result1 >> 16) & 65535;
              result1 &= 65535;
              temp = unchecked(x1 * y0);  // b * c
              result2 += (temp >> 16) & 65535;
              result1 += temp & 65535;
              result2 += (result1 >> 16) & 65535;
              result1 &= 65535;
              result3 = (result2 >> 16) & 65535;
              result2 &= 65535;
              temp = unchecked(x1 * y1);  // b * d
              result3 += (temp >> 16) & 65535;
              result2 += temp & 65535;
              result3 += (result2 >> 16) & 65535;
              result2 &= 65535;
              // Add carry
              x0 = unchecked((int)(result0 | (result1 << 16)));
              x1 = unchecked((int)(result2 | (result3 << 16)));
              int x2 = unchecked(x0 + carry);
              if (((x2 >> 31) == (x0 >> 31)) ? ((x2 & Int32.MaxValue) < (x0 &
              Int32.MaxValue)) : ((x2 >> 31) == 0)) {
                // Carry in addition
                x1 = unchecked(x1 + 1);
              }
              this.data[i] = x2;
              carry = x1;
            }
          }
          if (carry != 0) {
            if (this.wordCount >= this.data.Length) {
              var newdata = new int[this.wordCount + 20];
              Array.Copy(this.data, 0, newdata, 0, this.data.Length);
              this.data = newdata;
            }
            this.data[this.wordCount] = carry;
            ++this.wordCount;
          }
          // Calculate the correct data length
          while (this.wordCount != 0 && this.data[this.wordCount - 1] == 0) {
            --this.wordCount;
          }
        } else {
          if (this.data.Length > 0) {
            this.data[0] = 0;
          }
          this.wordCount = 0;
        }
        return this;
      }

      internal int Sign {
        get {
          return this.wordCount == 0 ? 0 : 1;
        }
      }

      internal MutableNumber SubtractInt(int other) {
        if (other < 0) {
     throw new ArgumentException("other (" + other + ") is less than " +
            "0 ");
        }
      if (other != 0) {
          unchecked {
            // Ensure a length of at least 1
            if (this.wordCount == 0) {
              if (this.data.Length == 0) {
                this.data = new int[4];
              }
              this.data[0] = 0;
              this.wordCount = 1;
            }
            int borrow;
            int u;
            int a = this.data[0];
            u = a - other;
            borrow = ((((a >> 31) == (u >> 31)) ?
                    ((a & Int32.MaxValue) < (u & Int32.MaxValue)) :
                    ((a >> 31) == 0)) || (a == u && other != 0)) ? 1 : 0;
            this.data[0] = (int)u;
            if (borrow != 0) {
              for (int i = 1; i < this.wordCount; ++i) {
                u = this.data[i] - borrow;
                borrow = (((this.data[i] >> 31) == (u >> 31)) ?
                ((this.data[i] & Int32.MaxValue) < (u & Int32.MaxValue)) :
                    ((this.data[i] >> 31) == 0)) ? 1 : 0;
                this.data[i] = (int)u;
              }
            }
            // Calculate the correct data length
            while (this.wordCount != 0 && this.data[this.wordCount - 1] == 0) {
              --this.wordCount;
            }
          }
        }
        return this;
      }

      internal MutableNumber Subtract(MutableNumber other) {
        unchecked {
          {
       // Console.WriteLine("" + this.data.Length + " " +
             // (other.data.Length));
            int neededSize = (this.wordCount > other.wordCount) ?
            this.wordCount : other.wordCount;
            if (this.data.Length < neededSize) {
              var newdata = new int[neededSize + 20];
              Array.Copy(this.data, 0, newdata, 0, this.data.Length);
              this.data = newdata;
            }
            neededSize = (this.wordCount < other.wordCount) ? this.wordCount :
            other.wordCount;
            var u = 0;
            var borrow = 0;
            for (var i = 0; i < neededSize; ++i) {
              int a = this.data[i];
              u = (a - other.data[i]) - borrow;
              borrow = ((((a >> 31) == (u >> 31)) ? ((a & Int32.MaxValue) <
              (u & Int32.MaxValue)) :
                    ((a >> 31) == 0)) || (a == u && other.data[i] !=
                    0)) ? 1 : 0;
              this.data[i] = (int)u;
            }
            if (borrow != 0) {
              for (int i = neededSize; i < this.wordCount; ++i) {
                int a = this.data[i];
                u = (a - other.data[i]) - borrow;
                borrow = ((((a >> 31) == (u >> 31)) ? ((a & Int32.MaxValue) <
                (u & Int32.MaxValue)) :
                    ((a >> 31) == 0)) || (a == u && other.data[i] !=
                    0)) ? 1 : 0;
                this.data[i] = (int)u;
              }
            }
            // Calculate the correct data length
            while (this.wordCount != 0 && this.data[this.wordCount - 1] == 0) {
              --this.wordCount;
            }
            return this;
          }
        }
      }

       internal MutableNumber Add(int augend) {
        if (augend < 0) {
   throw new ArgumentException("augend (" + augend + ") is less than " +
            "0 ");
        }
        unchecked {
        if (augend != 0) {
          var carry = 0;
          // Ensure a length of at least 1
          if (this.wordCount == 0) {
            if (this.data.Length == 0) {
              this.data = new int[4];
            }
            this.data[0] = 0;
            this.wordCount = 1;
          }
          for (var i = 0; i < this.wordCount; ++i) {
            int u;
            int a = this.data[i];
            u = (a + augend) + carry;
            carry = ((((u >> 31) == (a >> 31)) ? ((u & Int32.MaxValue) < (a &
            Int32.MaxValue)) :
                    ((u >> 31) == 0)) || (u == a && augend != 0)) ? 1 : 0;
            this.data[i] = u;
            if (carry == 0) {
              return this;
            }
            augend = 0;
          }
          if (carry != 0) {
            if (this.wordCount >= this.data.Length) {
              var newdata = new int[this.wordCount + 20];
              Array.Copy(this.data, 0, newdata, 0, this.data.Length);
              this.data = newdata;
            }
            this.data[this.wordCount] = carry;
            ++this.wordCount;
          }
        }
        // Calculate the correct data length
        while (this.wordCount != 0 && this.data[this.wordCount - 1] == 0) {
          --this.wordCount;
        }
        return this;
      }
    }
    }

    private int smallValue;  // if integerMode is 0
    private MutableNumber mnum;  // if integerMode is 1
    private EInteger largeValue;  // if integerMode is 2
    private int integerMode;

    internal FastInteger2(int value) {
      this.smallValue = value;
    }

    internal int AsInt32() {
      switch (this.integerMode) {
        case 0:
          return this.smallValue;
        case 1:
          return this.mnum.ToInt32();
        case 2:
          return (int)this.largeValue;
        default: throw new InvalidOperationException();
      }
    }

    internal static EInteger WordsToEInteger(int[] words) {
      int wordCount = words.Length;
      if (wordCount == 1 && (words[0] >> 31) == 0) {
        return (EInteger)((int)words[0]);
      }
      var bytes = new byte[(wordCount * 4) + 1];
      for (var i = 0; i < wordCount; ++i) {
        bytes[(i * 4) + 0] = (byte)(words[i] & 0xff);
        bytes[(i * 4) + 1] = (byte)((words[i] >> 8) & 0xff);
        bytes[(i * 4) + 2] = (byte)((words[i] >> 16) & 0xff);
        bytes[(i * 4) + 3] = (byte)((words[i] >> 24) & 0xff);
      }
      bytes[bytes.Length - 1] = (byte)0;
      return EInteger.FromBytes(bytes, true);
    }

    internal FastInteger2 SetInt(int val) {
      this.smallValue = val;
      this.integerMode = 0;
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.FastInteger2.Multiply(System.Int32)"]/*'/>
    internal FastInteger2 Multiply(int val) {
      if (val == 0) {
        this.smallValue = 0;
        this.integerMode = 0;
      } else {
        switch (this.integerMode) {
          case 0:
            bool apos = this.smallValue > 0L;
            bool bpos = val > 0L;
            if (
              (apos && ((!bpos && (Int32.MinValue / this.smallValue) > val) ||
                    (bpos && this.smallValue > (Int32.MaxValue / val)))) ||
              (!apos && ((!bpos && this.smallValue != 0L &&
                    (Int32.MaxValue / this.smallValue) > val) ||
                    (bpos && this.smallValue < (Int32.MinValue / val))))) {
              // would overflow, convert to large
              if (apos && bpos) {
                // if both operands are nonnegative
                // convert to mutable big integer
                this.integerMode = 1;
                this.mnum = new MutableNumber(this.smallValue);
                this.mnum.Multiply(val);
              } else {
                // if either operand is negative
                // convert to big integer
                this.integerMode = 2;
                this.largeValue = (EInteger)this.smallValue;
                this.largeValue *= (EInteger)val;
              }
            } else {
              smallValue *= val;
            }
            break;
          case 1:
            if (val < 0) {
              this.integerMode = 2;
              this.largeValue = this.mnum.ToEInteger();
              this.largeValue *= (EInteger)val;
            } else {
              mnum.Multiply(val);
            }
            break;
          case 2:
            this.largeValue *= (EInteger)val;
            break;
          default: throw new InvalidOperationException();
        }
      }
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.FastInteger2.Subtract(PeterO.Cbor.FastInteger2)"]/*'/>
    internal FastInteger2 Subtract(FastInteger2 val) {
      EInteger valValue;
      switch (this.integerMode) {
        case 0:
          if (val.integerMode == 0) {
            int vsv = val.smallValue;
            if ((vsv < 0 && Int32.MaxValue + vsv < this.smallValue) ||
                (vsv > 0 && Int32.MinValue + vsv > this.smallValue)) {
              // would overflow, convert to large
              this.integerMode = 2;
              this.largeValue = (EInteger)this.smallValue;
              this.largeValue -= (EInteger)vsv;
            } else {
              this.smallValue -= vsv;
            }
          } else {
            integerMode = 2;
            largeValue = (EInteger)smallValue;
            valValue = val.AsBigInteger();
            largeValue -= (EInteger)valValue;
          }
          break;
        case 1:
          if (val.integerMode == 1) {
            // NOTE: Mutable numbers are
            // currently always zero or positive
            this.mnum.Subtract(val.mnum);
          } else if (val.integerMode == 0 && val.smallValue >= 0) {
            mnum.SubtractInt(val.smallValue);
          } else {
            integerMode = 2;
            largeValue = mnum.ToEInteger();
            valValue = val.AsBigInteger();
            largeValue -= (EInteger)valValue;
          }
          break;
        case 2:
          valValue = val.AsBigInteger();
          this.largeValue -= (EInteger)valValue;
          break;
        default: throw new InvalidOperationException();
      }
      return this;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:PeterO.Cbor.FastInteger2.SubtractInt(System.Int32)"]/*'/>
    internal FastInteger2 SubtractInt(int val) {
      if (val == Int32.MinValue) {
        return this.AddInt(Int32.MaxValue).AddInt(1);
      }
      if (this.integerMode == 0) {
        if ((val < 0 && Int32.MaxValue + val < this.smallValue) ||
                (val > 0 && Int32.MinValue + val > this.smallValue)) {
          // would overflow, convert to large
          this.integerMode = 2;
          this.largeValue = (EInteger)this.smallValue;
          this.largeValue -= (EInteger)val;
        } else {
          this.smallValue -= val;
        }
        return this;
      }
      return this.AddInt(-val);
    }

    internal FastInteger2 Add(FastInteger2 val) {
      EInteger valValue;
      switch (this.integerMode) {
        case 0:
          if (val.integerMode == 0) {
            if ((this.smallValue < 0 && (int)val.smallValue < Int32.MinValue
            - this.smallValue) ||
                (this.smallValue > 0 && (int)val.smallValue > Int32.MaxValue
                - this.smallValue)) {
              // would overflow
              if (val.smallValue >= 0) {
                this.integerMode = 1;
                this.mnum = new MutableNumber(this.smallValue);
                this.mnum.Add(val.smallValue);
              } else {
                this.integerMode = 2;
                this.largeValue = (EInteger)this.smallValue;
                this.largeValue += (EInteger)val.smallValue;
              }
            } else {
              this.smallValue += val.smallValue;
            }
          } else {
            integerMode = 2;
            largeValue = (EInteger)smallValue;
            valValue = val.AsBigInteger();
            largeValue += (EInteger)valValue;
          }
          break;
        case 1:
          if (val.integerMode == 0 && val.smallValue >= 0) {
            this.mnum.Add(val.smallValue);
          } else {
            integerMode = 2;
            largeValue = mnum.ToEInteger();
            valValue = val.AsBigInteger();
            largeValue += (EInteger)valValue;
          }
          break;
        case 2:
          valValue = val.AsBigInteger();
          this.largeValue += (EInteger)valValue;
          break;
        default: throw new InvalidOperationException();
      }
      return this;
    }

    internal FastInteger2 AddInt(int val) {
      EInteger valValue;
      switch (this.integerMode) {
        case 0:
          if ((this.smallValue < 0 && (int)val < Int32.MinValue -
        this.smallValue) || (this.smallValue > 0 && (int)val >
            Int32.MaxValue - this.smallValue)) {
            // would overflow
            if (val >= 0) {
              this.integerMode = 1;
              this.mnum = new MutableNumber(this.smallValue);
              this.mnum.Add(val);
            } else {
              this.integerMode = 2;
              this.largeValue = (EInteger)this.smallValue;
              this.largeValue += (EInteger)val;
            }
          } else {
            smallValue += val;
          }
          break;
        case 1:
          if (val >= 0) {
            this.mnum.Add(val);
          } else {
            integerMode = 2;
            largeValue = mnum.ToEInteger();
            valValue = (EInteger)val;
            largeValue += (EInteger)valValue;
          }
          break;
        case 2:
          valValue = (EInteger)val;
          this.largeValue += (EInteger)valValue;
          break;
        default: throw new InvalidOperationException();
      }
      return this;
    }

    internal bool CanFitInInt32() {
      switch (this.integerMode) {
        case 0:
          return true;
        case 1:
          return this.mnum.CanFitInInt32();
          case 2: {
            return this.largeValue.CanFitInInt32();
          }
        default:
          throw new InvalidOperationException();
      }
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="P:PeterO.Cbor.FastInteger2.Sign"]/*'/>
    internal int Sign {
      get {
        switch (this.integerMode) {
          case 0:
          return (this.smallValue == 0) ? 0 : ((this.smallValue < 0) ? -1 :
              1);
          case 1:
            return this.mnum.Sign;
          case 2:
            return this.largeValue.Sign;
          default: return 0;
        }
      }
    }

    internal EInteger AsBigInteger() {
      switch (this.integerMode) {
        case 0:
          return EInteger.FromInt32(this.smallValue);
        case 1:
          return this.mnum.ToEInteger();
        case 2:
          return this.largeValue;
        default: throw new InvalidOperationException();
      }
    }
  }
}
