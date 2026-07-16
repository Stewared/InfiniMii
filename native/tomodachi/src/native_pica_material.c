#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "native_pica_material.h"

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef NPM_PI
#define NPM_PI 3.14159265358979323846
#endif

#define NPM_MATERIAL_MAGIC "THMSBIN\0"
#define NPM_LUT_MAGIC "THLUBIN\0"
#define NPM_ABI_VERSION 1u
#define NPM_ENDIAN_TAG 0x01020304u
#define NPM_MATERIAL_HEADER_SIZE 0xc0u
#define NPM_MODEL_STRIDE 0xa0u
#define NPM_TEXTURE_STRIDE 0xa0u
#define NPM_MATERIAL_STRIDE 0x880u
#define NPM_MESH_STRIDE 0x100u
#define NPM_LUT_HEADER_SIZE 0xa0u
#define NPM_LUT_STRIDE 0x60u
#define NPM_LUT_SAMPLER_STRIDE 0x250u

enum {
    NPM_COLOR_EMISSION = 0,
    NPM_COLOR_AMBIENT = 1,
    NPM_COLOR_DIFFUSE = 2,
    NPM_COLOR_SPECULAR0 = 3,
    NPM_COLOR_SPECULAR1 = 4,
    NPM_COLOR_CONSTANT0 = 5,
    NPM_COLOR_CONSTANT1 = 6,
    NPM_COLOR_CONSTANT2 = 7,
    NPM_COLOR_CONSTANT3 = 8,
    NPM_COLOR_CONSTANT4 = 9,
    NPM_COLOR_CONSTANT5 = 10,
    NPM_COLOR_COUNT = 11
};

enum {
    NPM_LUT_REFLEC_R = 0,
    NPM_LUT_REFLEC_G = 1,
    NPM_LUT_REFLEC_B = 2,
    NPM_LUT_DIST0 = 3,
    NPM_LUT_DIST1 = 4,
    NPM_LUT_FRESNEL = 5
};

typedef struct {
    char name[129];
    uint32_t first_material, material_count;
    uint32_t first_mesh, mesh_count;
} NpmModelRecord;

typedef struct {
    char name[129];
    uint32_t width, height, mipmap_size, hardware_format;
    uint32_t gl_format, gl_type;
    uint8_t *rgba;
    int owns_rgba;
} NpmTextureRecord;

typedef struct {
    char table_name[65];
    char sampler_name[65];
    uint32_t enabled, input, scale;
    int sampler_index;
} NpmLutReference;

typedef struct {
    char texture_path[129];
    uint32_t enabled;
    int32_t texture_index;
    uint32_t coord_defined;
    int32_t source_coord;
    uint32_t mapping_type;
    int32_t reference_camera;
    uint32_t transform_type;
    float scale[2], rotation, translation[2];
    float matrix[12];
    uint32_t wrap_u, wrap_v;
    uint32_t mag_filter, min_filter, mip_filter, combined_min_filter;
    float lod_bias;
    uint32_t min_lod, border_rgba;
} NpmTextureUnit;

typedef struct {
    uint32_t constant_selector;
    uint32_t source_raw;
    uint32_t operand_raw;
    uint32_t combiner_raw;
    uint32_t constant_rgba;
    uint32_t scale_raw;
    uint32_t update_flags;
} NpmTexEnvStage;

struct NpmMaterial {
    char name[65];
    uint32_t model_index, material_index;
    uint32_t flags, tex_coord_config, translucency_kind, used_coord_count;
    int32_t shader_desc_index, light_set_index, fog_index;
    NpmColor colors[NPM_COLOR_COUNT];
    float color_scale;
    uint32_t fragment_flags, lighting_translucency, fresnel_selector;
    int32_t bump_texture;
    uint32_t bump_mode, bump_renormalize;
    uint32_t fragment_lighting_enabled, hemisphere_lighting_enabled;
    NpmLutReference luts[NPM_MATERIAL_LUT_COUNT];
    NpmTextureUnit units[NPM_MAX_TEXTURE_UNITS];
    NpmColor texenv_buffer;
    uint32_t texenv_update_raw;
    NpmTexEnvStage stages[NPM_TEXENV_STAGE_COUNT];
    uint32_t polygon_offset_enabled, cull_mode;
    float polygon_offset;
    uint32_t alpha_raw, alpha_enabled, alpha_func, alpha_ref;
    uint32_t depth_flags, depth_raw;
    uint32_t blend_mode, blend_constant_rgba;
    uint32_t color_operation_raw, blend_function_raw, logical_op;
    uint32_t stencil_test_raw, stencil_op_raw;
};

typedef struct {
    char name[65];
    uint32_t model_index, mesh_index;
    int32_t shape_index, material_index;
    uint32_t visible, render_priority;
    int32_t mesh_node_index, primitive_index;
    char material_name[65], mesh_node_name[65];
} NpmMeshRecord;

typedef struct {
    char name[65];
    uint32_t first_sampler, sampler_count;
} NpmLutRecord;

typedef struct {
    char name[65];
    uint32_t absolute, sample_count;
    uint16_t quantized[256];
    double expanded[512];
} NpmLutSampler;

struct NpmMaterialSet {
    uint64_t source_length;
    uint8_t source_sha256[32];
    char source_name[65];
    NpmModelRecord *models;
    NpmTextureRecord *textures;
    NpmMaterial *materials;
    NpmMeshRecord *meshes;
    uint32_t model_count, texture_count, material_count, mesh_count;
    NpmLutRecord *luts;
    NpmLutSampler *lut_samplers;
    uint32_t lut_count, lut_sampler_count;
    uint64_t lut_source_length;
    uint8_t lut_source_sha256[32];
    char lut_source_name[65];
    NpmDiagnostics diagnostics;
};

static uint32_t npm_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t npm_rd64(const uint8_t *p) {
    return (uint64_t)npm_rd32(p) | ((uint64_t)npm_rd32(p + 4) << 32);
}

static float npm_rdf32(const uint8_t *p) {
    uint32_t bits = npm_rd32(p);
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void npm_copy_string(char *dst, size_t dst_size, const uint8_t *src, size_t src_size) {
    size_t length = 0;
    if (!dst_size) return;
    while (length < src_size && src[length]) length++;
    if (length >= dst_size) length = dst_size - 1;
    memcpy(dst, src, length);
    dst[length] = '\0';
}

static void npm_error(char *dst, size_t size, const char *format, ...) {
    va_list args;
    if (!dst || !size) return;
    va_start(args, format);
    vsnprintf(dst, size, format, args);
    va_end(args);
    dst[size - 1] = '\0';
}

static int npm_range(size_t size, uint32_t offset, uint32_t count, uint32_t stride) {
    uint64_t end = (uint64_t)offset + (uint64_t)count * (uint64_t)stride;
    return offset <= size && end <= size;
}

static int npm_read_file(const char *path, uint8_t **data_out, size_t *size_out,
    char *error, size_t error_size) {
    FILE *file;
    long length;
    uint8_t *data;
    if (!path || !data_out || !size_out) return 0;
    file = fopen(path, "rb");
    if (!file) {
        npm_error(error, error_size, "cannot open %s: %s", path, strerror(errno));
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        npm_error(error, error_size, "cannot size %s", path);
        fclose(file);
        return 0;
    }
    data = (uint8_t *)malloc((size_t)length ? (size_t)length : 1u);
    if (!data || ((size_t)length && fread(data, 1, (size_t)length, file) != (size_t)length)) {
        npm_error(error, error_size, "cannot read %s", path);
        free(data);
        fclose(file);
        return 0;
    }
    fclose(file);
    *data_out = data;
    *size_out = (size_t)length;
    return 1;
}

static NpmColor npm_color_word(uint32_t value) {
    NpmColor c;
    c.r = (double)(value & 255u) / 255.0;
    c.g = (double)((value >> 8) & 255u) / 255.0;
    c.b = (double)((value >> 16) & 255u) / 255.0;
    c.a = (double)((value >> 24) & 255u) / 255.0;
    return c;
}

static NpmColor npm_color_rgb(uint32_t rgb) {
    NpmColor c;
    c.r = (double)((rgb >> 16) & 255u) / 255.0;
    c.g = (double)((rgb >> 8) & 255u) / 255.0;
    c.b = (double)(rgb & 255u) / 255.0;
    c.a = 1.0;
    return c;
}

/* Small local SHA-256 implementation, used to reject sidecar/source mismatches. */
typedef struct {
    uint32_t h[8];
    uint64_t bytes;
    uint8_t block[64];
    size_t used;
} NpmSha256;

static uint32_t npm_rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

static void npm_sha256_block(NpmSha256 *s, const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64], a,b,c,d,e,f,g,h;
    int i;
    for (i = 0; i < 16; i++) {
        const uint8_t *p = block + i * 4;
        w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
            ((uint32_t)p[2] << 8) | p[3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = npm_rotr32(w[i-15],7) ^ npm_rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = npm_rotr32(w[i-2],17) ^ npm_rotr32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3];
    e=s->h[4]; f=s->h[5]; g=s->h[6]; h=s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1=npm_rotr32(e,6)^npm_rotr32(e,11)^npm_rotr32(e,25);
        uint32_t ch=(e&f)^((~e)&g), t1=h+S1+ch+k[i]+w[i];
        uint32_t S0=npm_rotr32(a,2)^npm_rotr32(a,13)^npm_rotr32(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c), t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void npm_sha256_init(NpmSha256 *s) {
    static const uint32_t initial[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(s->h, initial, sizeof(initial)); s->bytes=0; s->used=0;
}

static void npm_sha256_update(NpmSha256 *s, const uint8_t *p, size_t n) {
    s->bytes += n;
    while (n) {
        size_t take = 64u - s->used;
        if (take > n) take = n;
        memcpy(s->block + s->used, p, take); s->used += take; p += take; n -= take;
        if (s->used == 64u) { npm_sha256_block(s, s->block); s->used = 0; }
    }
}

static void npm_sha256_finish(NpmSha256 *s, uint8_t out[32]) {
    uint64_t bits = s->bytes * 8u;
    int i;
    s->block[s->used++] = 0x80;
    if (s->used > 56u) { memset(s->block+s->used,0,64u-s->used); npm_sha256_block(s,s->block); s->used=0; }
    memset(s->block+s->used,0,56u-s->used);
    for (i=0;i<8;i++) s->block[63-i]=(uint8_t)(bits>>(i*8));
    npm_sha256_block(s,s->block);
    for(i=0;i<8;i++){out[i*4]=(uint8_t)(s->h[i]>>24);out[i*4+1]=(uint8_t)(s->h[i]>>16);out[i*4+2]=(uint8_t)(s->h[i]>>8);out[i*4+3]=(uint8_t)s->h[i];}
}

static void npm_hash_bytes(const uint8_t *data, size_t size, uint8_t out[32]) {
    NpmSha256 s; npm_sha256_init(&s); npm_sha256_update(&s,data,size); npm_sha256_finish(&s,out);
}

void npm_material_set_init(NpmMaterialSet *set) { if (set) memset(set, 0, sizeof(*set)); }

void npm_material_set_free(NpmMaterialSet *set) {
    uint32_t i;
    if (!set) return;
    for (i=0;i<set->texture_count;i++) if (set->textures[i].owns_rgba) free(set->textures[i].rgba);
    free(set->models); free(set->textures); free(set->materials); free(set->meshes);
    free(set->luts); free(set->lut_samplers);
    memset(set,0,sizeof(*set));
}

NpmMaterialSet *npm_material_set_create(void) {
    NpmMaterialSet *set=(NpmMaterialSet *)calloc(1,sizeof(*set));
    return set;
}

void npm_material_set_destroy(NpmMaterialSet *set) { if(set){npm_material_set_free(set);free(set);} }

static void npm_clear_material_data(NpmMaterialSet *set) {
    uint32_t i;
    if (!set) return;
    for (i=0;i<set->texture_count;i++) if(set->textures[i].owns_rgba) free(set->textures[i].rgba);
    free(set->models); free(set->textures); free(set->materials); free(set->meshes);
    set->models=NULL; set->textures=NULL; set->materials=NULL; set->meshes=NULL;
    set->model_count=set->texture_count=set->material_count=set->mesh_count=0;
    set->source_length=0; memset(set->source_sha256,0,32); set->source_name[0]='\0';
}

static void npm_clear_lut_data(NpmMaterialSet *set) {
    if (!set) return;
    free(set->luts); free(set->lut_samplers);
    set->luts=NULL; set->lut_samplers=NULL; set->lut_count=set->lut_sampler_count=0;
    set->lut_source_length=0;memset(set->lut_source_sha256,0,32);set->lut_source_name[0]='\0';
}

static int npm_find_lut_sampler(const NpmMaterialSet *set, const char *table, const char *sampler) {
    uint32_t i,j;
    if (!set || !table || !sampler) return -1;
    for(i=0;i<set->lut_count;i++) {
        const NpmLutRecord *lut=&set->luts[i];
        if(strcmp(lut->name,table)!=0) continue;
        for(j=0;j<lut->sampler_count;j++) {
            uint32_t index=lut->first_sampler+j;
            if(index<set->lut_sampler_count && strcmp(set->lut_samplers[index].name,sampler)==0)
                return (int)index;
        }
    }
    /*
     * CTR CGFX stores this reference pair in the opposite semantic order in
     * Tomodachi's MTOBs (for example spc0_01/lutCommon).  SPICA preserves the
     * two raw fields.  Resolve that same exact pair reversed; never guess a
     * LUT from material or texture names.
     */
    for(i=0;i<set->lut_count;i++) {
        const NpmLutRecord *lut=&set->luts[i];
        if(strcmp(lut->name,sampler)!=0) continue;
        for(j=0;j<lut->sampler_count;j++) {
            uint32_t index=lut->first_sampler+j;
            if(index<set->lut_sampler_count && strcmp(set->lut_samplers[index].name,table)==0)
                return (int)index;
        }
    }
    return -1;
}

static void npm_resolve_lut_references(NpmMaterialSet *set) {
    uint32_t i,j,missing=0;
    if(!set) return;
    for(i=0;i<set->material_count;i++) for(j=0;j<NPM_MATERIAL_LUT_COUNT;j++) {
        NpmLutReference *ref=&set->materials[i].luts[j];
        ref->sampler_index=-1;
        if(ref->enabled) {
            ref->sampler_index=npm_find_lut_sampler(set,ref->table_name,ref->sampler_name);
            if(ref->sampler_index<0) missing++;
        }
    }
    set->diagnostics.unresolved_lut_references=missing;
    set->diagnostics.lut_count=set->lut_count;
    set->diagnostics.lut_sampler_count=set->lut_sampler_count;
}

int npm_load_material_sidecar(NpmMaterialSet *set, const char *path,
    char *error, size_t error_size) {
    uint8_t *data=NULL;
    size_t size=0;
    uint32_t file_size, model_off, model_stride, texture_off, texture_stride;
    uint32_t material_off, material_stride, mesh_off, mesh_stride;
    uint32_t i,j;
    if(error&&error_size) error[0]='\0';
    if(!set){npm_error(error,error_size,"null material set");return 0;}
    if(!npm_read_file(path,&data,&size,error,error_size)) return 0;
    if(size<NPM_MATERIAL_HEADER_SIZE || memcmp(data,NPM_MATERIAL_MAGIC,8)!=0 ||
       npm_rd32(data+8)!=NPM_ABI_VERSION || npm_rd32(data+12)!=NPM_ENDIAN_TAG ||
       npm_rd32(data+16)!=NPM_MATERIAL_HEADER_SIZE) {
        npm_error(error,error_size,"%s is not a THMSBIN v1 sidecar",path); free(data); return 0;
    }
    file_size=npm_rd32(data+0x14);
    if(file_size!=size){npm_error(error,error_size,"%s file-size field is %u, actual %zu",path,file_size,size);free(data);return 0;}
    model_off=npm_rd32(data+0x84); model_stride=npm_rd32(data+0x88);
    texture_off=npm_rd32(data+0x90); texture_stride=npm_rd32(data+0x94);
    material_off=npm_rd32(data+0x9c); material_stride=npm_rd32(data+0xa0);
    mesh_off=npm_rd32(data+0xa8); mesh_stride=npm_rd32(data+0xac);
    if(model_stride!=NPM_MODEL_STRIDE || texture_stride!=NPM_TEXTURE_STRIDE ||
       material_stride!=NPM_MATERIAL_STRIDE || mesh_stride!=NPM_MESH_STRIDE ||
       !npm_range(size,model_off,npm_rd32(data+0x80),model_stride) ||
       !npm_range(size,texture_off,npm_rd32(data+0x8c),texture_stride) ||
       !npm_range(size,material_off,npm_rd32(data+0x98),material_stride) ||
       !npm_range(size,mesh_off,npm_rd32(data+0xa4),mesh_stride)) {
        npm_error(error,error_size,"%s has invalid section bounds/strides",path);free(data);return 0;
    }

    npm_clear_material_data(set);
    set->model_count=npm_rd32(data+0x80); set->texture_count=npm_rd32(data+0x8c);
    set->material_count=npm_rd32(data+0x98); set->mesh_count=npm_rd32(data+0xa4);
    set->source_length=npm_rd64(data+0x18); memcpy(set->source_sha256,data+0x20,32);
    npm_copy_string(set->source_name,sizeof(set->source_name),data+0x40,64);
    set->models=(NpmModelRecord *)calloc(set->model_count?set->model_count:1,sizeof(*set->models));
    set->textures=(NpmTextureRecord *)calloc(set->texture_count?set->texture_count:1,sizeof(*set->textures));
    set->materials=(NpmMaterial *)calloc(set->material_count?set->material_count:1,sizeof(*set->materials));
    set->meshes=(NpmMeshRecord *)calloc(set->mesh_count?set->mesh_count:1,sizeof(*set->meshes));
    if(!set->models||!set->textures||!set->materials||!set->meshes) {
        npm_error(error,error_size,"out of memory loading %s",path);free(data);npm_clear_material_data(set);return 0;
    }

    for(i=0;i<set->model_count;i++) {
        const uint8_t *p=data+model_off+(size_t)i*model_stride;
        NpmModelRecord *r=&set->models[i];
        npm_copy_string(r->name,sizeof(r->name),p,128);
        r->first_material=npm_rd32(p+0x80);r->material_count=npm_rd32(p+0x84);
        r->first_mesh=npm_rd32(p+0x88);r->mesh_count=npm_rd32(p+0x8c);
        if((uint64_t)r->first_material+r->material_count>set->material_count ||
           (uint64_t)r->first_mesh+r->mesh_count>set->mesh_count) {
            npm_error(error,error_size,"%s model %u has invalid flattened ranges",path,i);free(data);npm_clear_material_data(set);return 0;
        }
    }
    for(i=0;i<set->texture_count;i++) {
        const uint8_t *p=data+texture_off+(size_t)i*texture_stride;
        NpmTextureRecord *r=&set->textures[i];
        npm_copy_string(r->name,sizeof(r->name),p,128);
        r->width=npm_rd32(p+0x80);r->height=npm_rd32(p+0x84);r->mipmap_size=npm_rd32(p+0x88);
        r->hardware_format=npm_rd32(p+0x8c);r->gl_format=npm_rd32(p+0x90);r->gl_type=npm_rd32(p+0x94);
    }
    for(i=0;i<set->material_count;i++) {
        const uint8_t *p=data+material_off+(size_t)i*material_stride;
        NpmMaterial *m=&set->materials[i];
        npm_copy_string(m->name,sizeof(m->name),p,64);
        m->model_index=npm_rd32(p+0x40);m->material_index=npm_rd32(p+0x44);
        m->flags=npm_rd32(p+0x48);m->tex_coord_config=npm_rd32(p+0x4c);
        m->translucency_kind=npm_rd32(p+0x50);m->used_coord_count=npm_rd32(p+0x54);
        m->shader_desc_index=(int32_t)npm_rd32(p+0x58);m->light_set_index=(int32_t)npm_rd32(p+0x5c);m->fog_index=(int32_t)npm_rd32(p+0x60);
        for(j=0;j<NPM_COLOR_COUNT;j++)m->colors[j]=npm_color_word(npm_rd32(p+0x68+j*4));
        m->color_scale=npm_rdf32(p+0x94);m->fragment_flags=npm_rd32(p+0x98);
        m->lighting_translucency=npm_rd32(p+0x9c);m->fresnel_selector=npm_rd32(p+0xa0);
        m->bump_texture=(int32_t)npm_rd32(p+0xa4);m->bump_mode=npm_rd32(p+0xa8);
        m->bump_renormalize=npm_rd32(p+0xac);m->fragment_lighting_enabled=npm_rd32(p+0xb0);
        m->hemisphere_lighting_enabled=npm_rd32(p+0xb4);
        for(j=0;j<NPM_MATERIAL_LUT_COUNT;j++) {
            const uint8_t *q=p+0xb8+j*0x90;NpmLutReference *ref=&m->luts[j];
            ref->enabled=npm_rd32(q);ref->input=npm_rd32(q+4);ref->scale=npm_rd32(q+8);ref->sampler_index=-1;
            npm_copy_string(ref->table_name,sizeof(ref->table_name),q+0x10,64);
            npm_copy_string(ref->sampler_name,sizeof(ref->sampler_name),q+0x50,64);
        }
        for(j=0;j<NPM_MAX_TEXTURE_UNITS;j++) {
            const uint8_t *q=p+0x418+j*0x110;NpmTextureUnit *u=&m->units[j];uint32_t k;
            npm_copy_string(u->texture_path,sizeof(u->texture_path),q,128);
            u->enabled=npm_rd32(q+0x80);u->texture_index=(int32_t)npm_rd32(q+0x84);u->coord_defined=npm_rd32(q+0x88);
            u->source_coord=(int32_t)npm_rd32(q+0x8c);u->mapping_type=npm_rd32(q+0x90);u->reference_camera=(int32_t)npm_rd32(q+0x94);u->transform_type=npm_rd32(q+0x98);
            u->scale[0]=npm_rdf32(q+0x9c);u->scale[1]=npm_rdf32(q+0xa0);u->rotation=npm_rdf32(q+0xa4);u->translation[0]=npm_rdf32(q+0xa8);u->translation[1]=npm_rdf32(q+0xac);
            for(k=0;k<12;k++)u->matrix[k]=npm_rdf32(q+0xb0+k*4);
            u->wrap_u=npm_rd32(q+0xe0);u->wrap_v=npm_rd32(q+0xe4);u->mag_filter=npm_rd32(q+0xe8);u->min_filter=npm_rd32(q+0xec);u->mip_filter=npm_rd32(q+0xf0);u->combined_min_filter=npm_rd32(q+0xf4);u->lod_bias=npm_rdf32(q+0xf8);u->min_lod=npm_rd32(q+0xfc);u->border_rgba=npm_rd32(q+0x100);
            if(u->enabled && (u->texture_index<0 || (uint32_t)u->texture_index>=set->texture_count)) set->diagnostics.invalid_material_references++;
        }
        m->texenv_buffer=npm_color_word(npm_rd32(p+0x748));m->texenv_update_raw=npm_rd32(p+0x74c);
        for(j=0;j<NPM_TEXENV_STAGE_COUNT;j++) {
            const uint8_t *q=p+0x750+j*0x20;NpmTexEnvStage *s=&m->stages[j];
            s->constant_selector=npm_rd32(q);s->source_raw=npm_rd32(q+4);s->operand_raw=npm_rd32(q+8);s->combiner_raw=npm_rd32(q+12);s->constant_rgba=npm_rd32(q+16);s->scale_raw=npm_rd32(q+20);s->update_flags=npm_rd32(q+24);
        }
        m->polygon_offset_enabled=npm_rd32(p+0x810);m->cull_mode=npm_rd32(p+0x814);m->polygon_offset=npm_rdf32(p+0x818);
        m->alpha_raw=npm_rd32(p+0x81c);m->alpha_enabled=npm_rd32(p+0x820);m->alpha_func=npm_rd32(p+0x824);m->alpha_ref=npm_rd32(p+0x828);
        m->depth_flags=npm_rd32(p+0x82c);m->depth_raw=npm_rd32(p+0x830);m->blend_mode=npm_rd32(p+0x834);m->blend_constant_rgba=npm_rd32(p+0x838);m->color_operation_raw=npm_rd32(p+0x83c);m->blend_function_raw=npm_rd32(p+0x840);m->logical_op=npm_rd32(p+0x844);m->stencil_test_raw=npm_rd32(p+0x848);m->stencil_op_raw=npm_rd32(p+0x84c);
    }
    for(i=0;i<set->mesh_count;i++) {
        const uint8_t *p=data+mesh_off+(size_t)i*mesh_stride;NpmMeshRecord *r=&set->meshes[i];
        npm_copy_string(r->name,sizeof(r->name),p,64);r->model_index=npm_rd32(p+0x40);r->mesh_index=npm_rd32(p+0x44);r->shape_index=(int32_t)npm_rd32(p+0x48);r->material_index=(int32_t)npm_rd32(p+0x4c);r->visible=npm_rd32(p+0x50);r->render_priority=npm_rd32(p+0x54);r->mesh_node_index=(int32_t)npm_rd32(p+0x58);r->primitive_index=(int32_t)npm_rd32(p+0x5c);npm_copy_string(r->material_name,sizeof(r->material_name),p+0x60,64);npm_copy_string(r->mesh_node_name,sizeof(r->mesh_node_name),p+0xa0,64);
        if(r->model_index>=set->model_count || r->material_index<0 || (uint32_t)r->material_index>=set->models[r->model_index].material_count) set->diagnostics.invalid_material_references++;
    }
    free(data);
    set->diagnostics.model_count=set->model_count;set->diagnostics.texture_count=set->texture_count;set->diagnostics.material_count=set->material_count;set->diagnostics.mesh_count=set->mesh_count;
    set->diagnostics.bound_texture_units=0;
    for(i=0;i<set->material_count;i++)for(j=0;j<3;j++)if(set->materials[i].units[j].enabled)set->diagnostics.bound_texture_units++;
    npm_resolve_lut_references(set);
    return 1;
}

int npm_load_lut_sidecar(NpmMaterialSet *set, const char *path,
    char *error, size_t error_size) {
    uint8_t *data=NULL;size_t size=0;uint32_t file_size,lut_off,lut_stride,sampler_off,sampler_stride,i,j;
    if(error&&error_size)error[0]='\0';
    if(!set){npm_error(error,error_size,"null material set");return 0;}
    if(!npm_read_file(path,&data,&size,error,error_size))return 0;
    if(size<NPM_LUT_HEADER_SIZE||memcmp(data,NPM_LUT_MAGIC,8)!=0||npm_rd32(data+8)!=NPM_ABI_VERSION||npm_rd32(data+12)!=NPM_ENDIAN_TAG||npm_rd32(data+16)!=NPM_LUT_HEADER_SIZE){npm_error(error,error_size,"%s is not a THLUBIN v1 sidecar",path);free(data);return 0;}
    file_size=npm_rd32(data+0x14);lut_off=npm_rd32(data+0x84);lut_stride=npm_rd32(data+0x88);sampler_off=npm_rd32(data+0x90);sampler_stride=npm_rd32(data+0x94);
    if(file_size!=size||lut_stride!=NPM_LUT_STRIDE||sampler_stride!=NPM_LUT_SAMPLER_STRIDE||!npm_range(size,lut_off,npm_rd32(data+0x80),lut_stride)||!npm_range(size,sampler_off,npm_rd32(data+0x8c),sampler_stride)){npm_error(error,error_size,"%s has invalid size/sections",path);free(data);return 0;}
    npm_clear_lut_data(set);set->lut_count=npm_rd32(data+0x80);set->lut_sampler_count=npm_rd32(data+0x8c);set->lut_source_length=npm_rd64(data+0x18);memcpy(set->lut_source_sha256,data+0x20,32);npm_copy_string(set->lut_source_name,sizeof(set->lut_source_name),data+0x40,64);
    set->luts=(NpmLutRecord *)calloc(set->lut_count?set->lut_count:1,sizeof(*set->luts));set->lut_samplers=(NpmLutSampler *)calloc(set->lut_sampler_count?set->lut_sampler_count:1,sizeof(*set->lut_samplers));
    if(!set->luts||!set->lut_samplers){npm_error(error,error_size,"out of memory loading %s",path);free(data);npm_clear_lut_data(set);return 0;}
    for(i=0;i<set->lut_count;i++){const uint8_t *p=data+lut_off+(size_t)i*lut_stride;NpmLutRecord *r=&set->luts[i];npm_copy_string(r->name,sizeof(r->name),p,64);r->first_sampler=npm_rd32(p+0x40);r->sampler_count=npm_rd32(p+0x44);if((uint64_t)r->first_sampler+r->sampler_count>set->lut_sampler_count){npm_error(error,error_size,"%s LUT %u has invalid sampler range",path,i);free(data);npm_clear_lut_data(set);return 0;}}
    for(i=0;i<set->lut_sampler_count;i++){
        const uint8_t *p=data+sampler_off+(size_t)i*sampler_stride;NpmLutSampler *s=&set->lut_samplers[i];npm_copy_string(s->name,sizeof(s->name),p,64);s->absolute=npm_rd32(p+0x40);s->sample_count=npm_rd32(p+0x44);if(s->sample_count!=256){npm_error(error,error_size,"%s LUT sampler %s has %u samples",path,s->name,s->sample_count);free(data);npm_clear_lut_data(set);return 0;}
        for(j=0;j<256;j++){uint16_t q=(uint16_t)(p[0x48+j*2]|((uint16_t)p[0x49+j*2]<<8));if(q>4095){npm_error(error,error_size,"%s LUT sample exceeds 12 bits",path);free(data);npm_clear_lut_data(set);return 0;}s->quantized[j]=q;}
        if(s->absolute){for(j=0;j<256;j++){s->expanded[j]=(double)s->quantized[0]/4095.0;s->expanded[j+256]=(double)s->quantized[j]/4095.0;}}
        else{for(j=0;j<256;j+=2){uint32_t k=j>>1;s->expanded[j]=(double)s->quantized[k+128]/4095.0;s->expanded[j+1]=s->expanded[j];s->expanded[j+256]=(double)s->quantized[k]/4095.0;s->expanded[j+257]=s->expanded[j+256];}}
    }
    free(data);npm_resolve_lut_references(set);return 1;
}

int npm_verify_lut_source(const NpmMaterialSet *set,const uint8_t *cgfx,size_t cgfx_size,
    char *error,size_t error_size) {
    uint8_t digest[32];if(error&&error_size)error[0]='\0';
    if(!set||!cgfx||!set->lut_count){npm_error(error,error_size,"LUT sidecar and CGFX are required");return 0;}
    if(set->lut_source_length!=(uint64_t)cgfx_size){npm_error(error,error_size,"LUT CGFX length mismatch for %s",set->lut_source_name);return 0;}
    npm_hash_bytes(cgfx,cgfx_size,digest);if(memcmp(digest,set->lut_source_sha256,32)!=0){npm_error(error,error_size,"LUT CGFX SHA-256 does not match sidecar for %s",set->lut_source_name);return 0;}return 1;
}

int npm_set_texture_image(NpmMaterialSet *set, uint32_t texture_index,
    NpmImageView image, int copy_pixels, char *error, size_t error_size) {
    NpmTextureRecord *texture;
    uint8_t *pixels=NULL;
    size_t byte_count;
    if(error&&error_size)error[0]='\0';
    if(!set||texture_index>=set->texture_count||image.width<=0||image.height<=0||!image.rgba){npm_error(error,error_size,"invalid texture image/index");return 0;}
    if((uint64_t)(uint32_t)image.width*(uint32_t)image.height>SIZE_MAX/4u){npm_error(error,error_size,"texture dimensions overflow");return 0;}
    byte_count=(size_t)image.width*(size_t)image.height*4u;
    if(copy_pixels){pixels=(uint8_t *)malloc(byte_count);if(!pixels){npm_error(error,error_size,"out of memory copying texture");return 0;}memcpy(pixels,image.rgba,byte_count);}
    texture=&set->textures[texture_index];
    if(texture->owns_rgba)free(texture->rgba);
    texture->rgba=copy_pixels?pixels:(uint8_t *)(uintptr_t)image.rgba;texture->owns_rgba=copy_pixels?1:0;
    texture->width=(uint32_t)image.width;texture->height=(uint32_t)image.height;
    set->diagnostics.decoded_textures=0;set->diagnostics.missing_textures=0;
    for(texture=set->textures;texture<set->textures+set->texture_count;texture++){if(texture->rgba)set->diagnostics.decoded_textures++;else set->diagnostics.missing_textures++;}
    return 1;
}

int npm_bind_cgfx_textures(NpmMaterialSet *set, const uint8_t *cgfx, size_t cgfx_size,
    char *error, size_t error_size) {
    uint8_t digest[32];
    uint32_t i;
    if(error&&error_size)error[0]='\0';
    if(!set||!cgfx||!set->texture_count){npm_error(error,error_size,"material sidecar and CGFX are required");return 0;}
    if(set->source_length!=(uint64_t)cgfx_size){npm_error(error,error_size,"CGFX length mismatch for %s: expected %llu, got %zu",set->source_name,(unsigned long long)set->source_length,cgfx_size);return 0;}
    npm_hash_bytes(cgfx,cgfx_size,digest);
    if(memcmp(digest,set->source_sha256,32)!=0){npm_error(error,error_size,"CGFX SHA-256 does not match sidecar for %s",set->source_name);return 0;}
#ifdef NPM_HAVE_TOMODACHI_RENDERER
    {
        size_t dict;
        uint32_t count;
        if(!cgfx_data_dict(cgfx,cgfx_size,1,&dict)){npm_error(error,error_size,"CGFX texture dictionary is missing");return 0;}
        count=cgfx_dict_count(cgfx,cgfx_size,dict);
        for(i=0;i<set->texture_count;i++) {
            uint32_t entry;
            int found=0;
            for(entry=0;entry<count;entry++) {
                size_t object;char name[128];
                if(!cgfx_dict_entry(cgfx,cgfx_size,dict,entry,&object,name,sizeof(name)))continue;
                if(strcmp(name,set->textures[i].name)!=0)continue;
                if(!cgfx_magic(cgfx,cgfx_size,object+4u,"TXOB"))continue;
                {
                    Image decoded;uint32_t average=0,format=0;
                    memset(&decoded,0,sizeof(decoded));
                    if(!cgfx_decode_texture(cgfx,cgfx_size,object,&decoded,&average,0xffffffu,&format))break;
                    {
                        int pixel;
                        /* The shared CGFX decoder returns these packed and ETC
                         * formats in the source decoder's B/G/R byte order.
                         * Native sampling consumes R/G/B, so normalize all five
                         * formats here exactly as DecodeBitmap does. */
                        if(format==0x02u||format==0x03u||format==0x04u||
                           format==0x0cu||format==0x0du) {
                            for(pixel=0;pixel<decoded.width*decoded.height;pixel++) {
                                uint8_t *rgba=decoded.rgba+(size_t)pixel*4u;
                                uint8_t red=rgba[0];rgba[0]=rgba[2];rgba[2]=red;
                            }
                        } else if(format==0x05u) {
                            /* The base decoder sees LA8's bytes in A/L order. */
                            for(pixel=0;pixel<decoded.width*decoded.height;pixel++) {
                                uint8_t *rgba=decoded.rgba+(size_t)pixel*4u;
                                uint8_t decoded_l=rgba[0],decoded_a=rgba[3];
                                rgba[0]=rgba[1]=rgba[2]=decoded_a;rgba[3]=decoded_l;
                            }
                        }
                    }
                    if(set->textures[i].owns_rgba)free(set->textures[i].rgba);
                    set->textures[i].rgba=decoded.rgba;set->textures[i].owns_rgba=1;
                    set->textures[i].width=(uint32_t)decoded.width;set->textures[i].height=(uint32_t)decoded.height;
                    set->textures[i].hardware_format=format;decoded.rgba=NULL;
                    found=1;
                }
                break;
            }
            if(!found){npm_error(error,error_size,"TXOB %s could not be decoded",set->textures[i].name);return 0;}
        }
    }
    set->diagnostics.decoded_textures=set->texture_count;set->diagnostics.missing_textures=0;
    return 1;
#else
    (void)i;
    npm_error(error,error_size,"npm_bind_cgfx_textures needs NPM_HAVE_TOMODACHI_RENDERER; use npm_set_texture_image instead");
    return 0;
#endif
}

const NpmMaterial *npm_material_for_index(const NpmMaterialSet *set,
    uint32_t model_index, uint32_t material_index) {
    const NpmModelRecord *model;
    if(!set||model_index>=set->model_count)return NULL;
    model=&set->models[model_index];if(material_index>=model->material_count)return NULL;
    return &set->materials[model->first_material+material_index];
}

const NpmMaterial *npm_material_for_mesh(const NpmMaterialSet *set,
    uint32_t model_index, uint32_t mesh_index) {
    const NpmModelRecord *model;const NpmMeshRecord *mesh;
    if(!set||model_index>=set->model_count)return NULL;model=&set->models[model_index];
    if(mesh_index>=model->mesh_count)return NULL;mesh=&set->meshes[model->first_mesh+mesh_index];
    if(mesh->material_index<0)return NULL;return npm_material_for_index(set,model_index,(uint32_t)mesh->material_index);
}

const char *npm_material_name(const NpmMaterial *material){return material?material->name:"";}
int npm_material_cull_mode(const NpmMaterial *material){return material?(int)material->cull_mode:3;}
uint32_t npm_material_depth_state(const NpmMaterial *material){return material?material->depth_raw:0;}
uint32_t npm_material_blend_state(const NpmMaterial *material){return material?material->blend_function_raw:0;}
int npm_material_depth_write_enabled(const NpmMaterial *material){
    /* Gfx.cs conversion explicitly enables DepthWrite for every CGFX MTOB. */
    return material != NULL;
}

int npm_material_cull_triangle(const NpmMaterial *material,double signed_area) {
    /* Screen-space positive area is treated as counter-clockwise/front. */
    if(!material)return 0;
    /* GfxFaceCulling.Always (2) is converted to PICA FrontFace by Gfx.cs. */
    switch(material->cull_mode){case 0:case 2:return signed_area>0.0;case 1:return signed_area<0.0;case 3:default:return 0;}
}

static double npm_clamp(double x,double lo,double hi){return x<lo?lo:(x>hi?hi:x);}
static double npm_sat(double x){return npm_clamp(x,0.0,1.0);}
static NpmVec3 npm_v3(double x,double y,double z){NpmVec3 v={x,y,z};return v;}
static NpmVec3 npm_v3_add(NpmVec3 a,NpmVec3 b){return npm_v3(a.x+b.x,a.y+b.y,a.z+b.z);}
static NpmVec3 npm_v3_sub(NpmVec3 a,NpmVec3 b){return npm_v3(a.x-b.x,a.y-b.y,a.z-b.z);}
static NpmVec3 npm_v3_mul(NpmVec3 a,double s){return npm_v3(a.x*s,a.y*s,a.z*s);}
static double npm_v3_dot(NpmVec3 a,NpmVec3 b){return a.x*b.x+a.y*b.y+a.z*b.z;}
static NpmVec3 npm_v3_cross(NpmVec3 a,NpmVec3 b){return npm_v3(a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x);}
static NpmVec3 npm_v3_norm(NpmVec3 a){double d=sqrt(npm_v3_dot(a,a));return d>1e-20?npm_v3_mul(a,1.0/d):npm_v3(0,0,1);}
static NpmColor npm_c(double r,double g,double b,double a){NpmColor c={r,g,b,a};return c;}
static NpmColor npm_c_add(NpmColor a,NpmColor b){return npm_c(a.r+b.r,a.g+b.g,a.b+b.b,a.a+b.a);}
static NpmColor npm_c_mul(NpmColor a,NpmColor b){return npm_c(a.r*b.r,a.g*b.g,a.b*b.b,a.a*b.a);}
static NpmColor npm_c_scale(NpmColor a,double s){return npm_c(a.r*s,a.g*s,a.b*s,a.a*s);}
static NpmColor npm_c_sat(NpmColor a){return npm_c(npm_sat(a.r),npm_sat(a.g),npm_sat(a.b),npm_sat(a.a));}

static void npm_context_base(NpmShaderContext *c,uint32_t catalog,uint32_t skin) {
    memset(c,0,sizeof(*c));c->catalog_color=catalog;c->skin_color=skin;
    c->camera_position=npm_v3(0.0,0.0,4.0);c->scene_ambient=npm_c(77.0/255.0,77.0/255.0,77.0/255.0,1.0);
    c->hemisphere_enabled=1;c->hemi_direction=npm_v3(0,1,0);c->hemi_lerp=0.5;
    c->light_count=2;
    /* Slot 0 is lightSet2 (shopFLgt), slot 1 is lightSet1 (faceFLgt). */
    c->lights[0].directional=0;c->lights[0].position=npm_v3(0,6,4);c->lights[0].direction=npm_v3(0,-0.624695,-0.78086877);
    c->lights[0].ambient=npm_c(0,0,0,1);c->lights[0].diffuse=npm_c(1,1,1,1);c->lights[0].specular0=npm_c(1,1,1,1);c->lights[0].specular1=npm_c(1,1,1,1);
    c->lights[1].directional=0;c->lights[1].position=npm_v3(1,0,4);c->lights[1].direction=npm_v3(0,-0.4472136,-0.8944272);
    c->lights[1].ambient=npm_c(0,0,0,0);c->lights[1].diffuse=npm_c(26.0/255.0,20.0/255.0,13.0/255.0,1);c->lights[1].specular0=npm_c(0,0,0,1);c->lights[1].specular1=npm_c(1.0/255.0,1.0/255.0,0,1);
}

void npm_shader_context_shop_headwear(NpmShaderContext *c,uint32_t catalog,uint32_t skin) {
    if(!c)return;npm_context_base(c,catalog,skin);
    c->hemi_ground=npm_c(128.0/255.0,102.0/255.0,77.0/255.0,1);
    c->hemi_sky=npm_c(77.0/255.0,102.0/255.0,77.0/255.0,1);
}

void npm_shader_context_shop_body(NpmShaderContext *c,uint32_t catalog,uint32_t skin) {
    if(!c)return;npm_context_base(c,catalog,skin);c->camera_position=npm_v3(0,0.75,4);
    c->lights[0].position=npm_v3(0,5,7);
    c->hemi_ground=npm_c(0.25,0.18,0.18,1);c->hemi_sky=npm_c(0.4,0.33,0.329843,1);
    /* Exact directional faceFLgt from obj_sCostume. */
    c->lights[1].directional=1;c->lights[1].position=npm_v3(0,0.70710677,-0.70710677);c->lights[1].direction=c->lights[1].position;
    c->lights[1].diffuse=npm_c(51.0/255.0,46.0/255.0,26.0/255.0,1);c->lights[1].specular0=npm_c(0,0,0,1);c->lights[1].specular1=npm_c(1.0/255.0,1.0/255.0,0,1);
}

NpmColor npm_vertex_primary_color(const NpmMaterial *m,const NpmShaderContext *ctx,
    NpmVec3 normal,NpmColor vertex,int has_vertex) {
    NpmColor result=npm_c(0,0,0,m?m->colors[NPM_COLOR_DIFFUSE].a:1);int contributed=0;
    if(!m)return npm_c(1,1,1,1);
    /* DefaultVertexShader's MatAmbi.w is the dedicated material ColorScale,
       not the authored ambient color's alpha channel.  Most Tomodachi CGFX
       materials store Ambient.a=0 and ColorScale=1, so conflating the two
       erases vertex colors and consequently the catalog-color combiner path. */
    if(has_vertex){double scale=m->color_scale;result.r=vertex.r*scale;result.g=vertex.g*scale;result.b=vertex.b*scale;result.a*=vertex.a;contributed=1;}
    if(ctx&&ctx->hemisphere_enabled&&m->hemisphere_lighting_enabled){double t=npm_v3_dot(npm_v3_norm(normal),npm_v3_norm(ctx->hemi_direction))*ctx->hemi_lerp+ctx->hemi_lerp;NpmColor hemi; t=npm_sat(t);hemi=npm_c(ctx->hemi_ground.r+(ctx->hemi_sky.r-ctx->hemi_ground.r)*t,ctx->hemi_ground.g+(ctx->hemi_sky.g-ctx->hemi_ground.g)*t,ctx->hemi_ground.b+(ctx->hemi_sky.b-ctx->hemi_ground.b)*t,1);result.r+=hemi.r*m->colors[NPM_COLOR_DIFFUSE].r;result.g+=hemi.g*m->colors[NPM_COLOR_DIFFUSE].g;result.b+=hemi.b*m->colors[NPM_COLOR_DIFFUSE].b;contributed=1;}
    if(!contributed)result=m->colors[NPM_COLOR_DIFFUSE];
    result.r=fmax(0,result.r);result.g=fmax(0,result.g);result.b=fmax(0,result.b);result.a=fmax(0,result.a);return result;
}

static int npm_wrap_index(int i,int size,uint32_t wrap,int *border) {
    int period,r;
    *border=0;if(size<=0){*border=1;return 0;}
    switch(wrap){
        case 0: return i<0?0:(i>=size?size-1:i);
        case 1: if(i<0||i>=size){*border=1;return 0;}return i;
        case 2: r=i%size;return r<0?r+size:r;
        case 3: period=size*2;r=i%period;if(r<0)r+=period;return r>=size?period-1-r:r;
        default:return i<0?0:(i>=size?size-1:i);
    }
}

static NpmColor npm_texel(const NpmTextureRecord *t,int x,int y,uint32_t wu,uint32_t wv,NpmColor border) {
    int bu,bv;size_t p;x=npm_wrap_index(x,(int)t->width,wu,&bu);y=npm_wrap_index(y,(int)t->height,wv,&bv);if(bu||bv)return border;
    p=((size_t)y*t->width+(uint32_t)x)*4u;return npm_c(t->rgba[p]/255.0,t->rgba[p+1]/255.0,t->rgba[p+2]/255.0,t->rgba[p+3]/255.0);
}

static NpmColor npm_sample_texture(const NpmTextureRecord *t,const NpmTextureUnit *u,double x,double y,double lod) {
    /* Gfx.cs maps mapper.MinFilter to H3D MagFilter and mapper.MagFilter to
       the minification base bit. Preserve that source conversion exactly. */
    NpmColor border=npm_color_word(u->border_rgba);uint32_t linear=(lod+u->lod_bias>0.0)?u->mag_filter:u->min_filter;
    if(!t||!t->rgba||!t->width||!t->height)return npm_c(1,1,1,1);
    if(!linear){int ix=(int)floor(x*t->width),iy=(int)floor(y*t->height);return npm_texel(t,ix,iy,u->wrap_u,u->wrap_v,border);}
    else{double fx=x*t->width-0.5,fy=y*t->height-0.5,ax,ay;int x0=(int)floor(fx),y0=(int)floor(fy);NpmColor c00,c10,c01,c11,r;ax=fx-floor(fx);ay=fy-floor(fy);c00=npm_texel(t,x0,y0,u->wrap_u,u->wrap_v,border);c10=npm_texel(t,x0+1,y0,u->wrap_u,u->wrap_v,border);c01=npm_texel(t,x0,y0+1,u->wrap_u,u->wrap_v,border);c11=npm_texel(t,x0+1,y0+1,u->wrap_u,u->wrap_v,border);r.r=(c00.r*(1-ax)+c10.r*ax)*(1-ay)+(c01.r*(1-ax)+c11.r*ax)*ay;r.g=(c00.g*(1-ax)+c10.g*ax)*(1-ay)+(c01.g*(1-ax)+c11.g*ax)*ay;r.b=(c00.b*(1-ax)+c10.b*ax)*(1-ay)+(c01.b*(1-ax)+c11.b*ax)*ay;r.a=(c00.a*(1-ax)+c10.a*ax)*(1-ay)+(c01.a*(1-ax)+c11.a*ax)*ay;return r;}
}

static NpmVec2 npm_transform_uv(const NpmTextureUnit *u,const NpmFragmentInput *in) {
    NpmVec2 src;double x,y,sx=u->scale[0],sy=u->scale[1],ca=cos(u->rotation),sa=sin(u->rotation),m11=sx*ca,m12=sy*sa,m21=-sx*sa,m22=sy*ca,m41,m42;
    if(u->mapping_type==2){NpmVec3 n=npm_v3_norm(in->normal);src.x=n.x*0.5+0.5;src.y=n.y*0.5+0.5;}
    else{int index=u->source_coord;if(index<0||index>2)index=0;src=in->uv[index];}
    /* Gfx.cs converts S/R/T and H3DTextureCoord.GetTransform rebuilds this
       matrix for the default vertex shader; the serialized dirty matrix is
       retained in the sidecar for auditing but is not what that code binds. */
    if(u->transform_type==1){m41=sx*(-ca*u->translation[0]-sa*u->translation[1]);m42=sy*(sa*u->translation[0]-ca*u->translation[1]);}
    else if(u->transform_type==2){m41=sx*ca*(-u->translation[0]-0.5)-sx*sa*(u->translation[1]-0.5)+0.5;m42=sy*sa*(-u->translation[0]-0.5)+sy*ca*(u->translation[1]-0.5)+0.5;}
    else{m41=sx*((0.5*sa-0.5*ca)+0.5-u->translation[0]);m42=sy*((-0.5*sa-0.5*ca)+0.5-u->translation[1]);}
    x=m11*src.x+m21*src.y+m41;y=m12*src.x+m22*src.y+m42;
    {NpmVec2 out={x,y};return out;}
}

static double npm_lut_scale(uint32_t value) {
    switch(value){case 0:return 1;case 1:return 2;case 2:return 4;case 3:return 8;case 6:return 0.25;case 7:return 0.5;default:return 1;}
}

static double npm_sample_lut(const NpmMaterialSet *set,const NpmLutReference *ref,double input) {
    const NpmLutSampler *s;double u,x,a,v0,v1;int i0,i1;
    if(!set||!ref||!ref->enabled||ref->sampler_index<0||(uint32_t)ref->sampler_index>=set->lut_sampler_count)return 1.0;
    s=&set->lut_samplers[ref->sampler_index];u=npm_sat((input+1.0)*0.5);x=u*512.0-0.5;i0=(int)floor(x);a=x-floor(x);i1=i0+1;if(i0<0)i0=0;if(i0>511)i0=511;if(i1<0)i1=0;if(i1>511)i1=511;v0=s->expanded[i0];v1=s->expanded[i1];return fmin((v0+(v1-v0)*a)*npm_lut_scale(ref->scale),1.0);
}

static double npm_lut_input(uint32_t selector,double nh,double vh,double nv,double ln,double ls,double phi) {
    switch(selector){case 0:return nh;case 1:return vh;case 2:return nv;case 3:return ln;case 4:return ls;case 5:return phi;default:return nh;}
}

static void npm_fragment_colors(const NpmMaterialSet *set,const NpmMaterial *m,
    const NpmShaderContext *ctx,const NpmFragmentInput *in,const NpmColor tex[3],
    NpmColor *primary,NpmColor *secondary) {
    NpmVec3 base_n=npm_v3_norm(in->normal),base_t=in->has_tangent?npm_v3_norm(in->tangent):npm_v3(1,0,0);
    NpmVec3 bitangent,surf_n=npm_v3(0,0,1),surf_t=npm_v3(1,0,0),normal,tangent,view;
    int first_light=0,last_light=ctx?ctx->light_count:0,li;
    *primary=npm_c_add(m->colors[NPM_COLOR_EMISSION],npm_c_mul(m->colors[NPM_COLOR_AMBIENT],ctx?ctx->scene_ambient:npm_c(0,0,0,1)));primary->a=1;
    *secondary=npm_c(0,0,0,1);
    if(!ctx||!m->fragment_lighting_enabled)return;
    if((m->bump_mode==1||m->bump_mode==2)&&m->bump_texture>=0&&m->bump_texture<3){NpmColor bump=tex[m->bump_texture];NpmVec3 v=npm_v3(bump.r*2-1,bump.g*2-1,bump.b*2-1);if(m->bump_mode==1)surf_n=v;else surf_t=v;}
    if(m->bump_renormalize){double z2=1.0-surf_n.x*surf_n.x-surf_n.y*surf_n.y;surf_n.z=sqrt(fmax(z2,0));}
    base_t=npm_v3_norm(npm_v3_sub(base_t,npm_v3_mul(base_n,npm_v3_dot(base_t,base_n))));if(npm_v3_dot(base_t,base_t)<1e-10)base_t=fabs(base_n.z)<0.9?npm_v3_norm(npm_v3_cross(npm_v3(0,0,1),base_n)):npm_v3(1,0,0);
    bitangent=npm_v3_norm(npm_v3_cross(base_n,base_t));
    normal=npm_v3_norm(npm_v3_add(npm_v3_add(npm_v3_mul(base_t,surf_n.x),npm_v3_mul(bitangent,surf_n.y)),npm_v3_mul(base_n,surf_n.z)));
    tangent=npm_v3_norm(npm_v3_add(npm_v3_add(npm_v3_mul(base_t,surf_t.x),npm_v3_mul(bitangent,surf_t.y)),npm_v3_mul(base_n,surf_t.z)));
    view=npm_v3_norm(npm_v3_sub(ctx->camera_position,in->position));
    /* obj_sHeadwear convention: MTOB lightSet2 -> shop slot 0; lightSet1 -> face slot 1. */
    if(ctx->light_count>=2){if(m->light_set_index==1){first_light=1;last_light=2;}else if(m->light_set_index==2){first_light=0;last_light=1;}}
    for(li=first_light;li<last_light&&li<NPM_MAX_FRAGMENT_LIGHTS;li++) {
        const NpmFragmentLight *l=&ctx->lights[li];NpmVec3 light=l->directional?npm_v3_norm(l->position):npm_v3_norm(npm_v3_sub(l->position,in->position));NpmVec3 halfv=npm_v3_norm(npm_v3_add(view,light));
        double cos_nh=npm_v3_dot(normal,halfv),cos_vh=npm_v3_dot(view,halfv),cos_nv=npm_v3_dot(normal,view),cos_ln=npm_v3_dot(light,normal),cos_ls=npm_v3_dot(light,npm_v3_norm(l->direction));
        NpmVec3 half_proj=npm_v3_sub(halfv,npm_v3_mul(normal,npm_v3_dot(normal,halfv)/fmax(npm_v3_dot(normal,normal),1e-20)));double cos_phi=npm_v3_dot(half_proj,tangent);double ln=l->two_sided_diffuse?fabs(cos_ln):fmax(cos_ln,0);double fi=(m->fragment_flags&1u)?(cos_ln<0?0:1):1;double d0=1,d1=1,g=1;NpmColor spec0=m->colors[NPM_COLOR_SPECULAR0],spec1=m->colors[NPM_COLOR_SPECULAR1],diff,spec;
        #define NPM_REF_SAMPLE(IDX) npm_sample_lut(set,&m->luts[(IDX)],npm_lut_input(m->luts[(IDX)].input,cos_nh,cos_vh,cos_nv,cos_ln,cos_ls,cos_phi))
        /* GfxFragmentFlags raw bits; Gfx.cs converts these to H3D flags. */
        if(m->fragment_flags&2u)d0=NPM_REF_SAMPLE(NPM_LUT_DIST0);
        if(m->fragment_flags&4u)d1=NPM_REF_SAMPLE(NPM_LUT_DIST1);
        if(m->fragment_flags&(4u|8u))g=ln/fmax(fabs(npm_v3_dot(halfv,halfv)),1e-20);
        if(m->fragment_flags&16u)spec1=npm_c(NPM_REF_SAMPLE(NPM_LUT_REFLEC_R),NPM_REF_SAMPLE(NPM_LUT_REFLEC_G),NPM_REF_SAMPLE(NPM_LUT_REFLEC_B),1);
        spec0=npm_c_scale(spec0,d0*((m->fragment_flags&4u)?g:1));spec1=npm_c_scale(spec1,d1*((m->fragment_flags&8u)?g:1));
        diff=npm_c_add(npm_c_mul(m->colors[NPM_COLOR_AMBIENT],l->ambient),npm_c_scale(npm_c_mul(m->colors[NPM_COLOR_DIFFUSE],l->diffuse),npm_sat(ln)));
        spec=npm_c_add(npm_c_mul(spec0,l->specular0),npm_c_mul(spec1,l->specular1));
        primary->r+=diff.r;primary->g+=diff.g;primary->b+=diff.b;secondary->r+=spec.r*fi;secondary->g+=spec.g*fi;secondary->b+=spec.b*fi;
        if(m->fresnel_selector&1u)primary->a=NPM_REF_SAMPLE(NPM_LUT_FRESNEL);
        if(m->fresnel_selector&2u)secondary->a=NPM_REF_SAMPLE(NPM_LUT_FRESNEL);
        #undef NPM_REF_SAMPLE
    }
    *primary=npm_c_sat(*primary);*secondary=npm_c_sat(*secondary);
}

static NpmColor npm_runtime_constant(const NpmMaterial *m,uint32_t selector,uint32_t catalog,uint32_t skin,uint32_t fallback) {
    if(selector==0)return npm_color_rgb(skin);if(selector==1)return npm_color_rgb(catalog);
    if(selector>=2&&selector<=5)return m->colors[NPM_COLOR_CONSTANT0+selector];
    if(selector>=6&&selector<=10)return m->colors[selector-6];
    return npm_color_word(fallback);
}

static NpmColor npm_texenv_source(uint32_t source,NpmColor primary,NpmColor fp,NpmColor fs,
    const NpmColor tex[3],NpmColor previous,NpmColor buffer,NpmColor constant) {
    switch(source){case 0:return primary;case 1:return fp;case 2:return fs;case 3:return tex[0];case 4:return tex[1];case 5:return tex[2];case 13:return buffer;case 14:return constant;case 15:return previous;default:return npm_c(0,0,0,1);}
}

static NpmColor npm_color_operand(NpmColor s,uint32_t op) {
    NpmColor r=s;uint32_t base=op&~1u;if(base==2)r=npm_c(s.a,s.a,s.a,s.a);else if(base==4)r=npm_c(s.r,s.r,s.r,s.r);else if(base==8)r=npm_c(s.g,s.g,s.g,s.g);else if(base==12)r=npm_c(s.b,s.b,s.b,s.b);if(op&1u)r=npm_c(1-r.r,1-r.g,1-r.b,1-r.a);return r;
}

static double npm_alpha_operand(NpmColor s,uint32_t op) {
    double r;switch(op&~1u){case 2:r=s.r;break;case 4:r=s.g;break;case 6:r=s.b;break;default:r=s.a;break;}return(op&1u)?1-r:r;
}

static NpmColor npm_combine_color(uint32_t mode,NpmColor a,NpmColor b,NpmColor c) {
    NpmColor r=npm_c(0,0,0,1);double *o=&r.r,*x=&a.r,*y=&b.r,*z=&c.r;int i;
    if(mode==6){double d=fmin(a.r*b.r+a.g*b.g+a.b*b.b,1);return npm_c(d,d,d,1);}if(mode==7){double d=fmin(a.r*b.r+a.g*b.g+a.b*b.b+a.a*b.a,1);return npm_c(d,d,d,1);}
    for(i=0;i<3;i++){switch(mode){case 0:o[i]=x[i];break;case 1:o[i]=x[i]*y[i];break;case 2:o[i]=fmin(x[i]+y[i],1);break;case 3:o[i]=npm_sat(x[i]+y[i]-0.5);break;case 4:o[i]=y[i]*(1-z[i])+x[i]*z[i];break;case 5:o[i]=fmax(x[i]-y[i],0);break;case 8:o[i]=fmin(x[i]*y[i]+z[i],1);break;case 9:o[i]=fmin(x[i]+y[i],1)*z[i];break;default:o[i]=x[i];break;}}return r;
}

static double npm_combine_alpha(uint32_t mode,double a,double b,double c) {
    switch(mode){case 0:return a;case 1:return a*b;case 2:return fmin(a+b,1);case 3:return npm_sat(a+b-0.5);case 4:return b*(1-c)+a*c;case 5:return fmax(a-b,0);case 6:case 7:return fmin(a*b*3,1);case 8:return fmin(a*b+c,1);case 9:return fmin(a+b,1)*c;default:return a;}
}

static double npm_texenv_scale(double x,uint32_t scale){return npm_sat(x*(double)(1u<<(scale&3u)));}

int npm_shade_fragment(NpmMaterialSet *set,const NpmMaterial *m,
    const NpmShaderContext *ctx,const NpmFragmentInput *in,NpmFragmentOutput *out) {
    NpmColor tex[3],primary,fp,fs,previous,buffer;NpmVec2 generated_uv[3];int unit,stage;
    if(!set||!m||!ctx||!in||!out)return 0;memset(out,0,sizeof(*out));set->diagnostics.shade_calls++;
    /* The PICA fragment stage samples transformed coordinate outputs, not a
       private transform owned by each texture sampler.  In the 011x layouts
       Texture2 is explicitly routed to TexCoord1 (SPICA's GenTexColor does
       the same); transforming the absent Texture2 mapper as UV0 shifts masks
       and can make catalog colors disappear entirely. */
    for(unit=0;unit<3;unit++)generated_uv[unit]=npm_transform_uv(&m->units[unit],in);
    for(unit=0;unit<3;unit++){const NpmTextureUnit *u=&m->units[unit];int coord=unit;NpmVec2 uv;if(unit==2&&(m->tex_coord_config==1u||m->tex_coord_config==2u||m->tex_coord_config==3u))coord=1;uv=generated_uv[coord];out->transformed_uv[unit]=uv;if(u->enabled&&u->texture_index>=0&&(uint32_t)u->texture_index<set->texture_count)tex[unit]=npm_sample_texture(&set->textures[u->texture_index],u,uv.x,uv.y,in->has_lod?in->lod:0);else tex[unit]=npm_c(1,1,1,1);out->texture_color[unit]=tex[unit];}
    primary=in->has_primary_color?in->primary_color:npm_vertex_primary_color(m,ctx,in->normal,in->vertex_color,in->has_vertex_color);
    npm_fragment_colors(set,m,ctx,in,tex,&fp,&fs);previous=primary;buffer=m->texenv_buffer;
    for(stage=0;stage<6;stage++){
        const NpmTexEnvStage *s=&m->stages[stage];NpmColor old=previous,constant=npm_runtime_constant(m,s->constant_selector,ctx->catalog_color,ctx->skin_color,s->constant_rgba);NpmColor co[3];double ao[3],alpha;NpmColor rgb;int k;
        for(k=0;k<3;k++){uint32_t cs=(s->source_raw>>(k*4))&15u,as=(s->source_raw>>(16+k*4))&15u,cop=(s->operand_raw>>(k*4))&15u,aop=(s->operand_raw>>(12+k*4))&7u;co[k]=npm_color_operand(npm_texenv_source(cs,primary,fp,fs,tex,old,buffer,constant),cop);ao[k]=npm_alpha_operand(npm_texenv_source(as,primary,fp,fs,tex,old,buffer,constant),aop);}
        rgb=npm_combine_color(s->combiner_raw&15u,co[0],co[1],co[2]);alpha=npm_combine_alpha((s->combiner_raw>>16)&15u,ao[0],ao[1],ao[2]);previous=npm_c(npm_texenv_scale(rgb.r,s->scale_raw&3u),npm_texenv_scale(rgb.g,s->scale_raw&3u),npm_texenv_scale(rgb.b,s->scale_raw&3u),npm_texenv_scale(alpha,(s->scale_raw>>16)&3u));
        /* PICA copies the previous stage, not this stage's newly computed output. */
        if(s->update_flags&1u){buffer.r=old.r;buffer.g=old.g;buffer.b=old.b;}if(s->update_flags&2u)buffer.a=old.a;
    }
    out->primary_color=primary;out->fragment_primary=fp;out->fragment_secondary=fs;out->color=previous;out->discarded=!npm_alpha_test_pass(m,previous.a);if(out->discarded)set->diagnostics.discarded_fragments++;return 1;
}

static int npm_test_func(uint32_t func,double a,double b,int quantized) {
    if(quantized){a=floor(npm_sat(a)*255.0+0.5);b=floor(npm_sat(b)*255.0+0.5);}
    switch(func&7u){case 0:return 0;case 1:return 1;case 2:return a==b;case 3:return a!=b;case 4:return a<b;case 5:return a<=b;case 6:return a>b;case 7:return a>=b;default:return 1;}
}

int npm_alpha_test_pass(const NpmMaterial *m,double alpha) {
    if(!m||!m->alpha_enabled)return 1;return npm_test_func(m->alpha_func,alpha,(double)(m->alpha_ref&255u)/255.0,1);
}

int npm_depth_test_pass(const NpmMaterial *m,double incoming,double stored) {
    if(!m||(m->depth_raw&1u)==0)return 1;return npm_test_func((m->depth_raw>>4)&7u,incoming,stored,0);
}

static double npm_blend_factor(uint32_t factor,int channel,NpmColor s,NpmColor d,NpmColor k) {
    const double *sp=&s.r,*dp=&d.r,*kp=&k.r;double sc=sp[channel],dc=dp[channel],kc=kp[channel];
    switch(factor&15u){case 0:return 0;case 1:return 1;case 2:return sc;case 3:return 1-sc;case 4:return dc;case 5:return 1-dc;case 6:return s.a;case 7:return 1-s.a;case 8:return d.a;case 9:return 1-d.a;case 10:return kc;case 11:return 1-kc;case 12:return k.a;case 13:return 1-k.a;case 14:return channel==3?1:fmin(s.a,1-d.a);default:return 1;}
}

static double npm_blend_equation(uint32_t eq,double s,double d) {
    switch(eq&7u){case 0:return s+d;case 1:return s-d;case 2:return d-s;case 3:return fmin(s,d);case 4:return fmax(s,d);default:return s+d;}
}

static uint8_t npm_color_byte(double x){return(uint8_t)floor(npm_sat(x)*255.0+0.5);}
static uint8_t npm_logic_byte(uint32_t op,uint8_t s,uint8_t d) {
    switch(op&15u){case 0:return 0;case 1:return s&d;case 2:return s&~d;case 3:return s;case 4:return 255;case 5:return(uint8_t)~s;case 6:return d;case 7:return(uint8_t)~d;case 8:return(uint8_t)~(s&d);case 9:return s|d;case 10:return(uint8_t)~(s|d);case 11:return s^d;case 12:return(uint8_t)~(s^d);case 13:return(uint8_t)(~s&d);case 14:return(uint8_t)(s|~d);case 15:return(uint8_t)(~s|d);default:return s;}
}

void npm_blend_pixel(const NpmMaterial *m,NpmColor source,NpmColor destination,NpmColor *result) {
    NpmColor constant;double *o,*s,*d;uint32_t color_eq,alpha_eq,cs,cd,as,ad;int i;
    if(!result)return;if(!m||m->blend_mode==0){*result=source;return;}
    if(m->blend_mode==3){uint8_t *dummy=NULL;(void)dummy;result->r=npm_logic_byte(m->logical_op,npm_color_byte(source.r),npm_color_byte(destination.r))/255.0;result->g=npm_logic_byte(m->logical_op,npm_color_byte(source.g),npm_color_byte(destination.g))/255.0;result->b=npm_logic_byte(m->logical_op,npm_color_byte(source.b),npm_color_byte(destination.b))/255.0;result->a=npm_logic_byte(m->logical_op,npm_color_byte(source.a),npm_color_byte(destination.a))/255.0;return;}
    constant=npm_color_word(m->blend_constant_rgba);color_eq=m->blend_function_raw&7u;alpha_eq=(m->blend_function_raw>>8)&7u;cs=(m->blend_function_raw>>16)&15u;cd=(m->blend_function_raw>>20)&15u;as=(m->blend_function_raw>>24)&15u;ad=(m->blend_function_raw>>28)&15u;o=&result->r;s=&source.r;d=&destination.r;
    for(i=0;i<3;i++)o[i]=npm_sat(npm_blend_equation(color_eq,s[i]*npm_blend_factor(cs,i,source,destination,constant),d[i]*npm_blend_factor(cd,i,source,destination,constant)));
    o[3]=npm_sat(npm_blend_equation(alpha_eq,s[3]*npm_blend_factor(as,3,source,destination,constant),d[3]*npm_blend_factor(ad,3,source,destination,constant)));
}

const NpmDiagnostics *npm_get_diagnostics(const NpmMaterialSet *set){return set?&set->diagnostics:NULL;}

void npm_reset_runtime_diagnostics(NpmMaterialSet *set){if(set){set->diagnostics.shade_calls=0;set->diagnostics.discarded_fragments=0;}}

void npm_print_diagnostics(const NpmMaterialSet *set,FILE *stream) {
    const NpmDiagnostics *d;if(!stream)stream=stderr;if(!set){fprintf(stream,"native_pica_material: (null)\n");return;}d=&set->diagnostics;
    fprintf(stream,"native_pica_material: models=%u textures=%u decoded=%u missing=%u materials=%u meshes=%u bound_units=%u LUTs=%u samplers=%u unresolved_LUTs=%u bad_refs=%u shades=%u discarded=%u\n",d->model_count,d->texture_count,d->decoded_textures,d->missing_textures,d->material_count,d->mesh_count,d->bound_texture_units,d->lut_count,d->lut_sampler_count,d->unresolved_lut_references,d->invalid_material_references,d->shade_calls,d->discarded_fragments);
}

const char *npm_shader_contract_id(void){return "tomodachi-native-pica-cgfx-v1:THMSBIN1:THLUBIN1:spica-texenv-fraglight:texel-center-wrap-neighbor";}
