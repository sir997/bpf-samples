// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::transmute_ptr_to_ref)]
#[allow(clippy::upper_case_acronyms)]
#[warn(single_use_lifetimes)]
mod imp {
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;

    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder
            .name("kprobe_bpf")
            .map("kprobe_b.rodata", false)
            .prog("do_unlinkat")
            .prog("do_unlinkat_exit");

        builder.build()
    }

    #[derive(Default)]
    pub struct KprobeSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'a> SkelBuilder<'a> for KprobeSkelBuilder {
        type Output = OpenKprobeSkel<'a>;
        fn open(mut self) -> libbpf_rs::Result<OpenKprobeSkel<'a>> {
            let mut skel_config = build_skel_config()?;
            let open_opts = self.obj_builder.opts(std::ptr::null());

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenKprobeSkel { obj, skel_config })
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
        ) -> libbpf_rs::Result<OpenKprobeSkel<'a>> {
            let mut skel_config = build_skel_config()?;

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenKprobeSkel { obj, skel_config })
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    pub struct OpenKprobeMaps<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenKprobeMaps<'_> {
        pub fn rodata(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("kprobe_b.rodata").unwrap()
        }
    }

    pub struct OpenKprobeMapsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenKprobeMapsMut<'_> {
        pub fn rodata(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("kprobe_b.rodata").unwrap()
        }
    }

    pub struct OpenKprobeProgs<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenKprobeProgs<'_> {
        pub fn do_unlinkat(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("do_unlinkat").unwrap()
        }

        pub fn do_unlinkat_exit(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("do_unlinkat_exit").unwrap()
        }
    }

    pub struct OpenKprobeProgsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenKprobeProgsMut<'_> {
        pub fn do_unlinkat(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("do_unlinkat").unwrap()
        }

        pub fn do_unlinkat_exit(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("do_unlinkat_exit").unwrap()
        }
    }

    pub mod kprobe_rodata_types {
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct rodata {}
    }

    pub struct OpenKprobeSkel<'a> {
        pub obj: libbpf_rs::OpenObject,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
    }

    impl<'a> OpenSkel for OpenKprobeSkel<'a> {
        type Output = KprobeSkel<'a>;
        fn load(mut self) -> libbpf_rs::Result<KprobeSkel<'a>> {
            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

            Ok(KprobeSkel {
                obj,
                skel_config: self.skel_config,
                links: KprobeLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            &self.obj
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            &mut self.obj
        }
    }
    impl OpenKprobeSkel<'_> {
        pub fn progs(&self) -> OpenKprobeProgs<'_> {
            OpenKprobeProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> OpenKprobeProgsMut<'_> {
            OpenKprobeProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> OpenKprobeMaps<'_> {
            OpenKprobeMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> OpenKprobeMapsMut<'_> {
            OpenKprobeMapsMut {
                inner: &mut self.obj,
            }
        }
    }

    pub struct KprobeMaps<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl KprobeMaps<'_> {
        pub fn rodata(&self) -> &libbpf_rs::Map {
            self.inner.map("kprobe_b.rodata").unwrap()
        }
    }

    pub struct KprobeMapsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl KprobeMapsMut<'_> {
        pub fn rodata(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("kprobe_b.rodata").unwrap()
        }
    }

    pub struct KprobeProgs<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl KprobeProgs<'_> {
        pub fn do_unlinkat(&self) -> &libbpf_rs::Program {
            self.inner.prog("do_unlinkat").unwrap()
        }

        pub fn do_unlinkat_exit(&self) -> &libbpf_rs::Program {
            self.inner.prog("do_unlinkat_exit").unwrap()
        }
    }

    pub struct KprobeProgsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl KprobeProgsMut<'_> {
        pub fn do_unlinkat(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("do_unlinkat").unwrap()
        }

        pub fn do_unlinkat_exit(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("do_unlinkat_exit").unwrap()
        }
    }

    #[derive(Default)]
    pub struct KprobeLinks {
        pub do_unlinkat: Option<libbpf_rs::Link>,
        pub do_unlinkat_exit: Option<libbpf_rs::Link>,
    }

    pub struct KprobeSkel<'a> {
        pub obj: libbpf_rs::Object,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        pub links: KprobeLinks,
    }

    unsafe impl Send for KprobeSkel<'_> {}
    unsafe impl Sync for KprobeSkel<'_> {}

    impl Skel for KprobeSkel<'_> {
        fn object(&self) -> &libbpf_rs::Object {
            &self.obj
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            &mut self.obj
        }

        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            self.links = KprobeLinks {
                do_unlinkat: (|| {
                    Ok(core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                        .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                })()?,
                do_unlinkat_exit: (|| {
                    Ok(core::ptr::NonNull::new(self.skel_config.prog_link_ptr(1)?)
                        .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                })()?,
            };

            Ok(())
        }
    }
    impl KprobeSkel<'_> {
        pub fn progs(&self) -> KprobeProgs<'_> {
            KprobeProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> KprobeProgsMut<'_> {
            KprobeProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> KprobeMaps<'_> {
            KprobeMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> KprobeMapsMut<'_> {
            KprobeMapsMut {
                inner: &mut self.obj,
            }
        }
    }

    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 176, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 11, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 107, 112, 114, 111, 98, 101, 47, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97,
        116, 0, 107, 114, 101, 116, 112, 114, 111, 98, 101, 47, 100, 111, 95, 117, 110, 108, 105,
        110, 107, 97, 116, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 111, 100, 97, 116, 97,
        0, 107, 112, 114, 111, 98, 101, 46, 98, 112, 102, 46, 99, 0, 95, 95, 95, 95, 100, 111, 95,
        117, 110, 108, 105, 110, 107, 97, 116, 46, 95, 95, 95, 95, 102, 109, 116, 0, 95, 95, 95,
        95, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 95, 101, 120, 105, 116, 46, 95,
        95, 95, 95, 102, 109, 116, 0, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 0, 100,
        111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 95, 101, 120, 105, 116, 0, 76, 73, 67, 69,
        78, 83, 69, 0, 46, 114, 101, 108, 107, 112, 114, 111, 98, 101, 47, 100, 111, 95, 117, 110,
        108, 105, 110, 107, 97, 116, 0, 46, 114, 101, 108, 107, 114, 101, 116, 112, 114, 111, 98,
        101, 47, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 0, 46, 66, 84, 70, 0, 46, 66,
        84, 70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 74, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 1, 0, 6,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 111, 0, 0, 0, 1, 0, 6, 0, 38, 0, 0, 0, 0, 0, 0, 0, 34, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        140, 0, 0, 0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0,
        18, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 169, 0, 0, 0, 17, 0, 5, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 121, 22, 104, 0, 0, 0, 0, 0, 133, 0, 0, 0,
        14, 0, 0, 0, 191, 7, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 0, 0, 0, 0, 15, 22, 0, 0, 0, 0, 0, 0,
        191, 161, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 248, 255, 255, 255, 183, 2, 0, 0, 8, 0, 0, 0, 191,
        99, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 113, 0, 0, 0, 121, 164, 248, 255, 0, 0, 0, 0, 119, 7,
        0, 0, 32, 0, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 38, 0, 0,
        0, 191, 115, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 6, 0, 0, 0, 183, 0, 0, 0, 0, 0, 0, 0, 149, 0,
        0, 0, 0, 0, 0, 0, 121, 22, 80, 0, 0, 0, 0, 0, 133, 0, 0, 0, 14, 0, 0, 0, 119, 0, 0, 0, 32,
        0, 0, 0, 24, 1, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 34, 0, 0, 0, 191,
        3, 0, 0, 0, 0, 0, 0, 191, 100, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 6, 0, 0, 0, 183, 0, 0, 0, 0,
        0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 68, 117, 97, 108, 32, 66, 83, 68, 47, 71, 80, 76, 0, 75,
        80, 82, 79, 66, 69, 32, 69, 78, 84, 82, 89, 32, 112, 105, 100, 32, 61, 32, 37, 100, 44, 32,
        102, 105, 108, 101, 110, 97, 109, 101, 32, 61, 32, 37, 115, 10, 0, 75, 80, 82, 79, 66, 69,
        32, 69, 88, 73, 84, 58, 32, 112, 105, 100, 32, 61, 32, 37, 100, 44, 32, 114, 101, 116, 32,
        61, 32, 37, 108, 100, 10, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 24,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 196,
        2, 0, 0, 196, 2, 0, 0, 214, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 1, 0, 0, 0, 21, 0,
        0, 4, 168, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 3, 0, 0, 0, 64, 0, 0,
        0, 17, 0, 0, 0, 3, 0, 0, 0, 128, 0, 0, 0, 21, 0, 0, 0, 3, 0, 0, 0, 192, 0, 0, 0, 25, 0, 0,
        0, 3, 0, 0, 0, 0, 1, 0, 0, 28, 0, 0, 0, 3, 0, 0, 0, 64, 1, 0, 0, 31, 0, 0, 0, 3, 0, 0, 0,
        128, 1, 0, 0, 35, 0, 0, 0, 3, 0, 0, 0, 192, 1, 0, 0, 39, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0,
        42, 0, 0, 0, 3, 0, 0, 0, 64, 2, 0, 0, 45, 0, 0, 0, 3, 0, 0, 0, 128, 2, 0, 0, 48, 0, 0, 0,
        3, 0, 0, 0, 192, 2, 0, 0, 51, 0, 0, 0, 3, 0, 0, 0, 0, 3, 0, 0, 54, 0, 0, 0, 3, 0, 0, 0, 64,
        3, 0, 0, 57, 0, 0, 0, 3, 0, 0, 0, 128, 3, 0, 0, 60, 0, 0, 0, 3, 0, 0, 0, 192, 3, 0, 0, 68,
        0, 0, 0, 3, 0, 0, 0, 0, 4, 0, 0, 71, 0, 0, 0, 3, 0, 0, 0, 64, 4, 0, 0, 74, 0, 0, 0, 3, 0,
        0, 0, 128, 4, 0, 0, 80, 0, 0, 0, 3, 0, 0, 0, 192, 4, 0, 0, 83, 0, 0, 0, 3, 0, 0, 0, 0, 5,
        0, 0, 86, 0, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 5, 0, 0,
        0, 100, 0, 0, 0, 1, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1, 108, 0, 0,
        0, 1, 0, 0, 12, 4, 0, 0, 0, 120, 0, 0, 0, 5, 0, 0, 4, 32, 0, 0, 0, 129, 0, 0, 0, 8, 0, 0,
        0, 0, 0, 0, 0, 134, 0, 0, 0, 8, 0, 0, 0, 64, 0, 0, 0, 139, 0, 0, 0, 5, 0, 0, 0, 128, 0, 0,
        0, 146, 0, 0, 0, 11, 0, 0, 0, 192, 0, 0, 0, 152, 0, 0, 0, 12, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 10, 0, 0, 0, 158, 0, 0, 0, 0, 0, 0, 1,
        1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
        0, 0, 9, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 163, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0,
        0, 183, 0, 0, 0, 1, 0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 10, 0, 0, 0,
        13, 0, 0, 0, 13, 0, 0, 0, 200, 0, 0, 0, 0, 0, 0, 14, 15, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 3, 0, 0, 0, 0, 9, 0, 0, 0, 13, 0, 0, 0, 38, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 14,
        17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 9, 0, 0, 0, 13, 0, 0, 0, 34,
        0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 14, 19, 0, 0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 0, 7, 0, 0,
        0, 0, 157, 2, 0, 0, 1, 0, 0, 15, 13, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 165, 2,
        0, 0, 2, 0, 0, 15, 72, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 20, 0, 0, 0, 38, 0,
        0, 0, 34, 0, 0, 0, 0, 112, 116, 95, 114, 101, 103, 115, 0, 114, 49, 53, 0, 114, 49, 52, 0,
        114, 49, 51, 0, 114, 49, 50, 0, 98, 112, 0, 98, 120, 0, 114, 49, 49, 0, 114, 49, 48, 0,
        114, 57, 0, 114, 56, 0, 97, 120, 0, 99, 120, 0, 100, 120, 0, 115, 105, 0, 100, 105, 0, 111,
        114, 105, 103, 95, 97, 120, 0, 105, 112, 0, 99, 115, 0, 102, 108, 97, 103, 115, 0, 115,
        112, 0, 115, 115, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 108, 111, 110, 103, 0, 99,
        116, 120, 0, 105, 110, 116, 0, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 0, 102,
        105, 108, 101, 110, 97, 109, 101, 0, 110, 97, 109, 101, 0, 117, 112, 116, 114, 0, 114, 101,
        102, 99, 110, 116, 0, 97, 110, 97, 109, 101, 0, 105, 110, 97, 109, 101, 0, 99, 104, 97,
        114, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 100,
        111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 95, 101, 120, 105, 116, 0, 76, 73, 67, 69,
        78, 83, 69, 0, 95, 95, 95, 95, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 46, 95,
        95, 95, 95, 102, 109, 116, 0, 95, 95, 95, 95, 100, 111, 95, 117, 110, 108, 105, 110, 107,
        97, 116, 95, 101, 120, 105, 116, 46, 95, 95, 95, 95, 102, 109, 116, 0, 97, 117, 100, 105,
        116, 95, 110, 97, 109, 101, 115, 0, 47, 114, 111, 111, 116, 47, 98, 112, 102, 45, 115, 97,
        109, 112, 108, 101, 115, 47, 114, 117, 115, 116, 45, 101, 120, 97, 109, 112, 108, 101, 115,
        47, 115, 114, 99, 47, 98, 112, 102, 47, 107, 112, 114, 111, 98, 101, 46, 98, 112, 102, 46,
        99, 0, 105, 110, 116, 32, 66, 80, 70, 95, 75, 80, 82, 79, 66, 69, 40, 100, 111, 95, 117,
        110, 108, 105, 110, 107, 97, 116, 44, 32, 105, 110, 116, 32, 100, 102, 100, 44, 32, 115,
        116, 114, 117, 99, 116, 32, 102, 105, 108, 101, 110, 97, 109, 101, 32, 42, 110, 97, 109,
        101, 41, 0, 32, 32, 32, 32, 112, 105, 100, 32, 61, 32, 98, 112, 102, 95, 103, 101, 116, 95,
        99, 117, 114, 114, 101, 110, 116, 95, 112, 105, 100, 95, 116, 103, 105, 100, 40, 41, 32,
        62, 62, 32, 51, 50, 59, 0, 32, 32, 32, 32, 102, 105, 108, 101, 110, 97, 109, 101, 32, 61,
        32, 66, 80, 70, 95, 67, 79, 82, 69, 95, 82, 69, 65, 68, 40, 110, 97, 109, 101, 44, 32, 110,
        97, 109, 101, 41, 59, 0, 32, 32, 32, 32, 98, 112, 102, 95, 112, 114, 105, 110, 116, 107,
        40, 34, 75, 80, 82, 79, 66, 69, 32, 69, 78, 84, 82, 89, 32, 112, 105, 100, 32, 61, 32, 37,
        100, 44, 32, 102, 105, 108, 101, 110, 97, 109, 101, 32, 61, 32, 37, 115, 92, 110, 34, 44,
        32, 112, 105, 100, 44, 32, 102, 105, 108, 101, 110, 97, 109, 101, 41, 59, 0, 105, 110, 116,
        32, 66, 80, 70, 95, 75, 82, 69, 84, 80, 82, 79, 66, 69, 40, 100, 111, 95, 117, 110, 108,
        105, 110, 107, 97, 116, 95, 101, 120, 105, 116, 44, 32, 108, 111, 110, 103, 32, 114, 101,
        116, 41, 0, 32, 32, 32, 32, 98, 112, 102, 95, 112, 114, 105, 110, 116, 107, 40, 34, 75, 80,
        82, 79, 66, 69, 32, 69, 88, 73, 84, 58, 32, 112, 105, 100, 32, 61, 32, 37, 100, 44, 32,
        114, 101, 116, 32, 61, 32, 37, 108, 100, 92, 110, 34, 44, 32, 112, 105, 100, 44, 32, 114,
        101, 116, 41, 59, 0, 48, 58, 49, 51, 0, 48, 58, 48, 0, 48, 58, 49, 48, 0, 108, 105, 99,
        101, 110, 115, 101, 0, 46, 114, 111, 100, 97, 116, 97, 0, 107, 112, 114, 111, 98, 101, 47,
        100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 0, 107, 114, 101, 116, 112, 114, 111,
        98, 101, 47, 100, 111, 95, 117, 110, 108, 105, 110, 107, 97, 116, 0, 0, 0, 0, 0, 0, 0, 159,
        235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 36, 0, 0, 0, 228, 0, 0, 0, 8, 1, 0, 0, 68,
        0, 0, 0, 8, 0, 0, 0, 173, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 192, 2, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 0, 0, 0, 173, 2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 17, 1, 0,
        0, 70, 1, 0, 0, 5, 36, 0, 0, 8, 0, 0, 0, 17, 1, 0, 0, 130, 1, 0, 0, 11, 56, 0, 0, 48, 0, 0,
        0, 17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 17, 1, 0, 0, 174, 1, 0, 0, 16, 60, 0,
        0, 80, 0, 0, 0, 17, 1, 0, 0, 174, 1, 0, 0, 16, 60, 0, 0, 88, 0, 0, 0, 17, 1, 0, 0, 130, 1,
        0, 0, 38, 56, 0, 0, 96, 0, 0, 0, 17, 1, 0, 0, 216, 1, 0, 0, 5, 64, 0, 0, 136, 0, 0, 0, 17,
        1, 0, 0, 70, 1, 0, 0, 5, 36, 0, 0, 192, 2, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 17, 1, 0, 0, 33,
        2, 0, 0, 5, 84, 0, 0, 8, 0, 0, 0, 17, 1, 0, 0, 130, 1, 0, 0, 11, 100, 0, 0, 16, 0, 0, 0,
        17, 1, 0, 0, 130, 1, 0, 0, 38, 100, 0, 0, 24, 0, 0, 0, 17, 1, 0, 0, 79, 2, 0, 0, 5, 104, 0,
        0, 72, 0, 0, 0, 17, 1, 0, 0, 33, 2, 0, 0, 5, 84, 0, 0, 16, 0, 0, 0, 173, 2, 0, 0, 2, 0, 0,
        0, 0, 0, 0, 0, 2, 0, 0, 0, 143, 2, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 7, 0, 0, 0, 148, 2, 0, 0,
        0, 0, 0, 0, 192, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 152, 2, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 48, 1, 0, 0, 0, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 1, 0, 0, 0,
        6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 184, 2, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0,
        0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 3, 0, 0, 0, 0, 0, 0, 13,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 66, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 3, 0, 0, 0,
        0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 177, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        104, 3, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0,
        0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 120, 3, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0,
        0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 226, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 3, 0, 0, 0, 0, 0, 0, 178, 5, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 9, 0, 0, 0, 0, 0, 0, 108, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}