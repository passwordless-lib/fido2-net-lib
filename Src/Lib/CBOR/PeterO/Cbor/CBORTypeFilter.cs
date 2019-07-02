/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="T:CBORTypeFilter"]/*'/>
  [Obsolete("May be removed without replacement.")]
  public sealed class CBORTypeFilter {
    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.Any"]/*'/>
    public static readonly CBORTypeFilter Any = new CBORTypeFilter().WithAny();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.ByteString"]/*'/>
    public static readonly CBORTypeFilter ByteString = new
      CBORTypeFilter().WithByteString();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.NegativeInteger"]/*'/>
    public static readonly CBORTypeFilter NegativeInteger = new
      CBORTypeFilter().WithNegativeInteger();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.None"]/*'/>
    public static readonly CBORTypeFilter None = new CBORTypeFilter();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.TextString"]/*'/>
    public static readonly CBORTypeFilter TextString = new
      CBORTypeFilter().WithTextString();

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="F:CBORTypeFilter.UnsignedInteger"]/*'/>
    public static readonly CBORTypeFilter UnsignedInteger = new
      CBORTypeFilter().WithUnsignedInteger();

    private bool any;
    private bool anyArrayLength;
    private int arrayLength;
    private bool arrayMinLength;
    private CBORTypeFilter[] elements;
    private bool floatingpoint;
    private EInteger[] tags;
    private int types;

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.ArrayIndexAllowed(System.Int32)"]/*'/>
    public bool ArrayIndexAllowed(int index) {
   return (this.types & (1 << 4)) != 0 && index >= 0 &&
        (this.anyArrayLength ||
        ((this.arrayMinLength || index < this.arrayLength) && index >=
                    0));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.ArrayLengthMatches(System.Int32)"]/*'/>
    public bool ArrayLengthMatches(int length) {
      return (this.types & (1 << 4)) != 0 && (this.anyArrayLength ||
                (this.arrayMinLength ? this.arrayLength >= length :
                this.arrayLength == length));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.ArrayLengthMatches(System.Int64)"]/*'/>
    public bool ArrayLengthMatches(long length) {
      return (this.types & (1 << 4)) != 0 && (this.anyArrayLength ||
                (this.arrayMinLength ? this.arrayLength >= length :
                this.arrayLength == length));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.ArrayLengthMatches(PeterO.Numbers.EInteger)"]/*'/>
    public bool ArrayLengthMatches(EInteger bigLength) {
      if (bigLength == null) {
        throw new ArgumentNullException(nameof(bigLength));
      }
      return ((this.types & (1 << 4)) == 0) && (this.anyArrayLength ||
        ((!this.arrayMinLength &&
        bigLength.CompareTo((EInteger)this.arrayLength) == 0) ||
        (this.arrayMinLength &&
        bigLength.CompareTo((EInteger)this.arrayLength) >= 0)));
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.GetSubFilter(System.Int32)"]/*'/>
    public CBORTypeFilter GetSubFilter(int index) {
      if (this.anyArrayLength || this.any) {
        return Any;
      }
      if (index < 0) {
        return None;
      }
      if (index >= this.arrayLength) {
        // Index is out of bounds
        return this.arrayMinLength ? Any : None;
      }
      if (this.elements == null) {
        return Any;
      }
      if (index >= this.elements.Length) {
        // Index is greater than the number of elements for
        // which a type is defined
        return Any;
      }
      return this.elements[index];
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.GetSubFilter(System.Int64)"]/*'/>
    public CBORTypeFilter GetSubFilter(long index) {
      if (this.anyArrayLength || this.any) {
        return Any;
      }
      if (index < 0) {
        return None;
      }
      if (index >= this.arrayLength) {
        // Index is out of bounds
        return this.arrayMinLength ? Any : None;
      }
      if (this.elements == null) {
        return Any;
      }
      // NOTE: Index shouldn't be greater than Int32.MaxValue,
      // since the length is an int
      if (index >= this.elements.Length) {
        // Index is greater than the number of elements for
        // which a type is defined
        return Any;
      }
      return this.elements[(int)index];
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.MajorTypeMatches(System.Int32)"]/*'/>
    public bool MajorTypeMatches(int type) {
#if DEBUG
      if (type < 0) {
        throw new ArgumentException("type (" + type + ") is less than 0");
      }
      if (type > 7) {
        throw new ArgumentException("type (" + type + ") is more than " + "7");
      }
#endif

      return type >= 0 && type <= 7 && (this.types & (1 << type)) != 0;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.NonFPSimpleValueAllowed"]/*'/>
    public bool NonFPSimpleValueAllowed() {
      return this.MajorTypeMatches(7) && !this.floatingpoint;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.TagAllowed(System.Int32)"]/*'/>
    public bool TagAllowed(int tag) {
      return this.any || this.TagAllowed((EInteger)tag);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.TagAllowed(System.Int64)"]/*'/>
    public bool TagAllowed(long longTag) {
      return this.any || this.TagAllowed((EInteger)longTag);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.TagAllowed(PeterO.Numbers.EInteger)"]/*'/>
    public bool TagAllowed(EInteger bigTag) {
      if (bigTag == null) {
        throw new ArgumentNullException(nameof(bigTag));
      }
      if (bigTag.Sign < 0) {
        return false;
      }
      if (this.any) {
        return true;
      }
      if ((this.types & (1 << 6)) == 0) {
        return false;
      }
      if (this.tags == null) {
        return true;
      }
      foreach (EInteger tag in this.tags) {
        if (bigTag.Equals(tag)) {
          return true;
        }
      }
      return false;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithArrayAnyLength"]/*'/>
    public CBORTypeFilter WithArrayAnyLength() {
      if (this.any) {
        return this;
      }
      if (this.arrayLength < 0) {
        throw new ArgumentException("this.arrayLength (" + this.arrayLength +
          ") is less than 0");
      }
      if (this.arrayLength < this.elements.Length) {
        throw new ArgumentException("this.arrayLength (" + this.arrayLength +
          ") is less than " + this.elements.Length);
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 4;
      filter.anyArrayLength = true;
      return filter;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithArrayExactLength(System.Int32,CBORTypeFilter[])"]/*'/>
    public CBORTypeFilter WithArrayExactLength(
  int arrayLength,
  params CBORTypeFilter[] elements) {
      if (this.any) {
        return this;
      }
      if (elements == null) {
        throw new ArgumentNullException(nameof(elements));
      }
      if (arrayLength < 0) {
        throw new ArgumentException("arrayLength (" + arrayLength +
          ") is less than 0");
      }
      if (arrayLength < elements.Length) {
        throw new ArgumentException("arrayLength (" + arrayLength +
          ") is less than " + elements.Length);
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 4;
      filter.arrayLength = arrayLength;
      filter.arrayMinLength = false;
      filter.elements = new CBORTypeFilter[elements.Length];
      Array.Copy(elements, filter.elements, elements.Length);
      return filter;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithArrayMinLength(System.Int32,CBORTypeFilter[])"]/*'/>
    public CBORTypeFilter WithArrayMinLength(
  int arrayLength,
  params CBORTypeFilter[] elements) {
      if (this.any) {
        return this;
      }
      if (elements == null) {
        throw new ArgumentNullException(nameof(elements));
      }
      if (arrayLength < 0) {
        throw new ArgumentException("arrayLength (" + arrayLength +
          ") is less than 0");
      }
      if (arrayLength < elements.Length) {
        throw new ArgumentException("arrayLength (" + arrayLength +
          ") is less than " + elements.Length);
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 4;
      filter.arrayLength = arrayLength;
      filter.arrayMinLength = true;
      filter.elements = new CBORTypeFilter[elements.Length];
      Array.Copy(elements, filter.elements, elements.Length);
      return filter;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithByteString"]/*'/>
    public CBORTypeFilter WithByteString() {
      return this.WithType(2).WithTags(25);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithFloatingPoint"]/*'/>
    public CBORTypeFilter WithFloatingPoint() {
      if (this.any) {
        return this;
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 4;
      filter.floatingpoint = true;
      return filter;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithMap"]/*'/>
    public CBORTypeFilter WithMap() {
      return this.WithType(5);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithNegativeInteger"]/*'/>
    public CBORTypeFilter WithNegativeInteger() {
      return this.WithType(1);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithTags(System.Int32[])"]/*'/>
    public CBORTypeFilter WithTags(params int[] tags) {
      if (this.any) {
        return this;
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 6;  // Always include the "tag" major type
      var startIndex = 0;
      if (filter.tags != null) {
        var newTags = new EInteger[tags.Length + filter.tags.Length];
        Array.Copy(filter.tags, newTags, filter.tags.Length);
        startIndex = filter.tags.Length;
        filter.tags = newTags;
      } else {
        filter.tags = new EInteger[tags.Length];
      }
      for (var i = 0; i < tags.Length; ++i) {
        filter.tags[startIndex + i] = (EInteger)tags[i];
      }
      return filter;
    }

    internal CBORTypeFilter WithTags(params EInteger[] tags) {
      if (this.any) {
        return this;
      }
      for (var i = 0; i < tags.Length; ++i) {
        if (tags[i] == null) {
          throw new ArgumentNullException(nameof(tags));
        }
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << 6;  // Always include the "tag" major type
      var startIndex = 0;
      if (filter.tags != null) {
        var newTags = new EInteger[tags.Length + filter.tags.Length];
        Array.Copy(filter.tags, newTags, filter.tags.Length);
        startIndex = filter.tags.Length;
        filter.tags = newTags;
      } else {
        filter.tags = new EInteger[tags.Length];
      }
      Array.Copy(tags, 0, filter.tags, startIndex, tags.Length);
      return filter;
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithTextString"]/*'/>
    public CBORTypeFilter WithTextString() {
      return this.WithType(3).WithTags(25);
    }

    /// <include file='../../docs.xml'
    /// path='docs/doc[@name="M:CBORTypeFilter.WithUnsignedInteger"]/*'/>
    public CBORTypeFilter WithUnsignedInteger() {
      return this.WithType(0);
    }

    private CBORTypeFilter Copy() {
      var filter = new CBORTypeFilter();
      filter.any = this.any;
      filter.types = this.types;
      filter.floatingpoint = this.floatingpoint;
      filter.arrayLength = this.arrayLength;
      filter.anyArrayLength = this.anyArrayLength;
      filter.arrayMinLength = this.arrayMinLength;
      filter.elements = this.elements;
      filter.tags = this.tags;
      return filter;
    }

    private CBORTypeFilter WithAny() {
      if (this.any) {
        return this;
      }
      CBORTypeFilter filter = this.Copy();
      filter.any = true;
      filter.anyArrayLength = true;
      filter.types = 0xff;
      return filter;
    }

    private CBORTypeFilter WithType(int type) {
      if (this.any) {
        return this;
      }
      CBORTypeFilter filter = this.Copy();
      filter.types |= 1 << type;
      return filter;
    }
  }
}
