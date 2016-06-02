#!/bin/bash -e

if [ ! -e unicorn ]
then
	git clone --depth=1 https://github.com/unicorn-engine/unicorn
else
	cd unicorn
	git pull || echo "WARNING: unable to pull unicorn"
	cd ..
fi


cat <<END > unicorn.diff
diff --git a/qemu/target-i386/cpu.h b/qemu/target-i386/cpu.h
index 4628a8d..8cc951f 100644
--- a/qemu/target-i386/cpu.h
+++ b/qemu/target-i386/cpu.h
@@ -1315,7 +1315,7 @@ void update_fp_status(CPUX86State *env);
 
 static inline uint32_t cpu_compute_eflags(CPUX86State *env)
 {
-    return env->eflags0 | cpu_cc_compute_all(env, CC_OP) | (env->df & DF_MASK);
+    return (env->eflags0 & ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK)) | cpu_cc_compute_all(env, CC_OP) | (env->df & DF_MASK);
 }
 
 /* NOTE: the translator must set DisasContext.cc_op to CC_OP_EFLAGS
END

cd unicorn
git stash
git apply ../unicorn.diff
make -j install PREFIX=$VIRTUAL_ENV
cd bindings/python
make -j install PREFIX=$VIRTUAL_ENV
cd ../../..

if [ -e $VIRTUAL_ENV/lib/python2.7/site-packages/unicorn ]
then
	cd $VIRTUAL_ENV/lib/python2.7/site-packages/unicorn
	ln -sf ../../../libunicorn.so .
else
	cd $VIRTUAL_ENV/site-packages/unicorn
	ln -sf ../../lib/libunicorn.so .
fi
cd -

python -c "import unicorn; print 'Unicorn successfully imported.'"
