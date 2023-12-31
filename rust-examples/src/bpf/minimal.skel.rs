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
            .name("minimal_bpf")
            .map("minimal_.bss", true)
            .map("minimal_.rodata", false)
            .prog("handle_tp");

        builder.build()
    }

    #[derive(Default)]
    pub struct MinimalSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'a> SkelBuilder<'a> for MinimalSkelBuilder {
        type Output = OpenMinimalSkel<'a>;
        fn open(mut self) -> libbpf_rs::Result<OpenMinimalSkel<'a>> {
            let mut skel_config = build_skel_config()?;
            let open_opts = self.obj_builder.opts(std::ptr::null());

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenMinimalSkel { obj, skel_config })
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
        ) -> libbpf_rs::Result<OpenMinimalSkel<'a>> {
            let mut skel_config = build_skel_config()?;

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenMinimalSkel { obj, skel_config })
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    pub struct OpenMinimalMaps<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenMinimalMaps<'_> {
        pub fn bss(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("minimal_.bss").unwrap()
        }

        pub fn rodata(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("minimal_.rodata").unwrap()
        }
    }

    pub struct OpenMinimalMapsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenMinimalMapsMut<'_> {
        pub fn bss(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("minimal_.bss").unwrap()
        }

        pub fn rodata(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("minimal_.rodata").unwrap()
        }
    }

    pub struct OpenMinimalProgs<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenMinimalProgs<'_> {
        pub fn handle_tp(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("handle_tp").unwrap()
        }
    }

    pub struct OpenMinimalProgsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenMinimalProgsMut<'_> {
        pub fn handle_tp(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("handle_tp").unwrap()
        }
    }

    pub mod minimal_bss_types {
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct bss {
            pub mpid: i32,
        }
    }

    pub mod minimal_rodata_types {
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct rodata {}
    }

    pub struct OpenMinimalSkel<'a> {
        pub obj: libbpf_rs::OpenObject,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
    }

    impl<'a> OpenSkel for OpenMinimalSkel<'a> {
        type Output = MinimalSkel<'a>;
        fn load(mut self) -> libbpf_rs::Result<MinimalSkel<'a>> {
            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

            Ok(MinimalSkel {
                obj,
                skel_config: self.skel_config,
                links: MinimalLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            &self.obj
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            &mut self.obj
        }
    }
    impl OpenMinimalSkel<'_> {
        pub fn progs(&self) -> OpenMinimalProgs<'_> {
            OpenMinimalProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> OpenMinimalProgsMut<'_> {
            OpenMinimalProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> OpenMinimalMaps<'_> {
            OpenMinimalMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> OpenMinimalMapsMut<'_> {
            OpenMinimalMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn bss(&mut self) -> &'_ mut minimal_bss_types::bss {
            unsafe {
                std::mem::transmute::<*mut std::ffi::c_void, &'_ mut minimal_bss_types::bss>(
                    self.skel_config.map_mmap_ptr(0).unwrap(),
                )
            }
        }
    }

    pub struct MinimalMaps<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl MinimalMaps<'_> {
        pub fn bss(&self) -> &libbpf_rs::Map {
            self.inner.map("minimal_.bss").unwrap()
        }

        pub fn rodata(&self) -> &libbpf_rs::Map {
            self.inner.map("minimal_.rodata").unwrap()
        }
    }

    pub struct MinimalMapsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl MinimalMapsMut<'_> {
        pub fn bss(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("minimal_.bss").unwrap()
        }

        pub fn rodata(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("minimal_.rodata").unwrap()
        }
    }

    pub struct MinimalProgs<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl MinimalProgs<'_> {
        pub fn handle_tp(&self) -> &libbpf_rs::Program {
            self.inner.prog("handle_tp").unwrap()
        }
    }

    pub struct MinimalProgsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl MinimalProgsMut<'_> {
        pub fn handle_tp(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("handle_tp").unwrap()
        }
    }

    #[derive(Default)]
    pub struct MinimalLinks {
        pub handle_tp: Option<libbpf_rs::Link>,
    }

    pub struct MinimalSkel<'a> {
        pub obj: libbpf_rs::Object,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        pub links: MinimalLinks,
    }

    unsafe impl Send for MinimalSkel<'_> {}
    unsafe impl Sync for MinimalSkel<'_> {}

    impl Skel for MinimalSkel<'_> {
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

            self.links = MinimalLinks {
                handle_tp: (|| {
                    Ok(core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                        .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                })()?,
            };

            Ok(())
        }
    }
    impl MinimalSkel<'_> {
        pub fn progs(&self) -> MinimalProgs<'_> {
            MinimalProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> MinimalProgsMut<'_> {
            MinimalProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> MinimalMaps<'_> {
            MinimalMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> MinimalMapsMut<'_> {
            MinimalMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn bss(&mut self) -> &'_ mut minimal_bss_types::bss {
            unsafe {
                std::mem::transmute::<*mut std::ffi::c_void, &'_ mut minimal_bss_types::bss>(
                    self.skel_config.map_mmap_ptr(0).unwrap(),
                )
            }
        }
    }

    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 10, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 116, 112, 47, 115, 121, 115, 99, 97, 108, 108, 115, 47, 115, 121, 115, 95, 101, 110,
        116, 101, 114, 95, 119, 114, 105, 116, 101, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 98,
        115, 115, 0, 46, 114, 111, 100, 97, 116, 97, 0, 109, 105, 110, 105, 109, 97, 108, 46, 98,
        112, 102, 46, 99, 0, 76, 66, 66, 48, 95, 50, 0, 104, 97, 110, 100, 108, 101, 95, 116, 112,
        46, 95, 95, 95, 95, 102, 109, 116, 0, 104, 97, 110, 100, 108, 101, 95, 116, 112, 0, 109,
        112, 105, 100, 0, 76, 73, 67, 69, 78, 83, 69, 0, 46, 114, 101, 108, 116, 112, 47, 115, 121,
        115, 99, 97, 108, 108, 115, 47, 115, 121, 115, 95, 101, 110, 116, 101, 114, 95, 119, 114,
        105, 116, 101, 0, 46, 66, 84, 70, 0, 46, 66, 84, 70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 4, 0, 241, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 3, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 87, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 105, 0, 0, 0, 18, 0, 3,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 0, 17, 0, 5, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0, 0, 17, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13,
        0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 14, 0, 0, 0, 119, 0, 0, 0, 32, 0, 0, 0, 24, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 17, 0, 0, 0, 0, 0, 0, 93, 1, 5, 0, 0, 0, 0, 0, 24, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 28, 0, 0, 0, 191, 3, 0, 0, 0, 0, 0,
        0, 133, 0, 0, 0, 6, 0, 0, 0, 183, 0, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 68, 117,
        97, 108, 32, 66, 83, 68, 47, 71, 80, 76, 0, 0, 0, 0, 66, 80, 70, 32, 116, 114, 105, 103,
        103, 101, 114, 101, 100, 32, 102, 114, 111, 109, 32, 80, 73, 68, 32, 37, 100, 46, 10, 0, 0,
        0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 5, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 16, 1, 0, 0, 16, 1, 0, 0, 46, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 3, 0, 0, 0, 1, 0, 0, 0, 1,
        0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1, 9, 0, 0, 0, 1, 0, 0, 12, 2, 0, 0,
        0, 19, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 5,
        0, 0, 0, 7, 0, 0, 0, 13, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 44, 0,
        0, 0, 0, 0, 0, 14, 6, 0, 0, 0, 1, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 14, 3, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 10, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 10, 0, 0, 0, 7,
        0, 0, 0, 28, 0, 0, 0, 57, 0, 0, 0, 0, 0, 0, 14, 11, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0, 0, 1,
        0, 0, 15, 13, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 5, 1, 0, 0, 1, 0, 0, 15, 4, 0,
        0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 10, 1, 0, 0, 1, 0, 0, 15, 28, 0, 0, 0, 12, 0, 0,
        0, 0, 0, 0, 0, 28, 0, 0, 0, 0, 99, 116, 120, 0, 105, 110, 116, 0, 104, 97, 110, 100, 108,
        101, 95, 116, 112, 0, 99, 104, 97, 114, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69,
        95, 84, 89, 80, 69, 95, 95, 0, 76, 73, 67, 69, 78, 83, 69, 0, 109, 112, 105, 100, 0, 104,
        97, 110, 100, 108, 101, 95, 116, 112, 46, 95, 95, 95, 95, 102, 109, 116, 0, 47, 114, 111,
        111, 116, 47, 98, 112, 102, 45, 115, 97, 109, 112, 108, 101, 115, 47, 114, 117, 115, 116,
        45, 101, 120, 97, 109, 112, 108, 101, 115, 47, 115, 114, 99, 47, 98, 112, 102, 47, 109,
        105, 110, 105, 109, 97, 108, 46, 98, 112, 102, 46, 99, 0, 32, 32, 32, 32, 105, 110, 116,
        32, 112, 105, 100, 32, 61, 32, 98, 112, 102, 95, 103, 101, 116, 95, 99, 117, 114, 114, 101,
        110, 116, 95, 112, 105, 100, 95, 116, 103, 105, 100, 40, 41, 32, 62, 62, 32, 51, 50, 59, 0,
        32, 32, 32, 32, 105, 102, 32, 40, 112, 105, 100, 32, 33, 61, 32, 109, 112, 105, 100, 41, 0,
        32, 32, 32, 32, 98, 112, 102, 95, 112, 114, 105, 110, 116, 107, 40, 34, 66, 80, 70, 32,
        116, 114, 105, 103, 103, 101, 114, 101, 100, 32, 102, 114, 111, 109, 32, 80, 73, 68, 32,
        37, 100, 46, 92, 110, 34, 44, 32, 112, 105, 100, 41, 59, 0, 125, 0, 108, 105, 99, 101, 110,
        115, 101, 0, 46, 98, 115, 115, 0, 46, 114, 111, 100, 97, 116, 97, 0, 116, 112, 47, 115,
        121, 115, 99, 97, 108, 108, 115, 47, 115, 121, 115, 95, 101, 110, 116, 101, 114, 95, 119,
        114, 105, 116, 101, 0, 0, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 20, 0,
        0, 0, 108, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 18, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 4, 0, 0, 0, 16, 0, 0, 0, 18, 1, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 75, 0, 0, 0, 129, 0, 0, 0,
        15, 44, 0, 0, 8, 0, 0, 0, 75, 0, 0, 0, 129, 0, 0, 0, 42, 44, 0, 0, 16, 0, 0, 0, 75, 0, 0,
        0, 177, 0, 0, 0, 16, 48, 0, 0, 40, 0, 0, 0, 75, 0, 0, 0, 177, 0, 0, 0, 9, 48, 0, 0, 48, 0,
        0, 0, 75, 0, 0, 0, 198, 0, 0, 0, 5, 68, 0, 0, 88, 0, 0, 0, 75, 0, 0, 0, 251, 0, 0, 0, 1,
        80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 216, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 1, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 0, 0, 0, 1, 0, 0, 0,
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 2, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0, 0, 0,
        8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 2, 0, 0, 0, 0, 0, 0, 4, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        58, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 2, 0, 0, 0, 0,
        0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96,
        2, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0,
        0, 16, 0, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 2, 0, 0, 0, 0, 0, 0, 86, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 4, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
