using System.Buffers.Binary;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Syroot.NintenTools.NSW.Bfres;
using Syroot.NintenTools.NSW.Bfres.Helpers;

if (args.Length >= 3 && args[0] == "--animation-index")
{
    string outputPath = Path.GetFullPath(args[1]);
    string[] inputPaths = args.Skip(2).Select(Path.GetFullPath).ToArray();
    var resources = new List<AnimationResourceCatalog>();
    foreach (string animationPath in inputPaths)
    {
        byte[] sourceBytes = File.ReadAllBytes(animationPath);
        using var source = new MemoryStream(sourceBytes, writable: false);
        var animationResource = new ResFile(source);
        var resourceCatalog = new AnimationResourceCatalog
        {
            Source = animationPath,
            ResourceName = animationResource.Name,
            ByteLength = sourceBytes.LongLength,
            Sha256 = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant(),
        };
        foreach (SkeletalAnim animation in animationResource.SkeletalAnims)
        {
            resourceCatalog.SkeletalAnimations.Add(new SkeletalAnimationCatalog
            {
                Name = animation.Name,
                Path = animation.Path,
                FrameCount = animation.FrameCount,
                Loop = animation.Loop,
                Baked = animation.Baked,
                RotationMode = animation.FlagsRotate.ToString(),
                ScaleMode = animation.FlagsScale.ToString(),
                BoneNames = animation.BoneAnims.Select(bone => bone.Name).ToArray(),
                CurveCount = animation.BoneAnims.Sum(bone => bone.Curves.Count),
            });
        }
        resources.Add(resourceCatalog);
    }
    Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
    File.WriteAllText(
        outputPath,
        JsonSerializer.Serialize(resources, new JsonSerializerOptions { WriteIndented = true }) + "\n",
        new UTF8Encoding(false));
    Console.WriteLine($"Indexed {resources.Sum(resource => resource.SkeletalAnimations.Count)} skeletal animation(s) to {outputPath}");
    return 0;
}

if (args.Length == 4 && args[0] == "--animation-dump")
{
    string inputAnimationPath = Path.GetFullPath(args[1]);
    string requestedAnimationName = args[2];
    string outputPath = Path.GetFullPath(args[3]);
    byte[] sourceBytes = File.ReadAllBytes(inputAnimationPath);
    using var source = new MemoryStream(sourceBytes, writable: false);
    var animationResource = new ResFile(source);
    SkeletalAnim animation = animationResource.SkeletalAnims.Single(
        item => string.Equals(item.Name, requestedAnimationName, StringComparison.Ordinal));
    var dump = new SkeletalAnimationDump
    {
        Source = inputAnimationPath,
        SourceByteLength = sourceBytes.LongLength,
        SourceSha256 = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant(),
        ResourceName = animationResource.Name,
        Name = animation.Name,
        Path = animation.Path,
        FrameCount = animation.FrameCount,
        Loop = animation.Loop,
        Baked = animation.Baked,
        RotationMode = animation.FlagsRotate.ToString(),
        ScaleMode = animation.FlagsScale.ToString(),
    };
    for (int index = 0; index < animation.BoneAnims.Count; index++)
    {
        BoneAnim bone = animation.BoneAnims[index];
        var boneDump = new BoneAnimationDump
        {
            Index = index,
            Name = bone.Name,
            BindIndex = index < animation.BindIndices.Length ? animation.BindIndices[index] : ushort.MaxValue,
            BaseFlags = bone.FlagsBase.ToString(),
            CurveFlags = bone.FlagsCurve.ToString(),
            TransformFlags = bone.FlagsTransform.ToString(),
            BaseScale = [bone.BaseData.Scale.X, bone.BaseData.Scale.Y, bone.BaseData.Scale.Z],
            BaseRotation = [bone.BaseData.Rotate.X, bone.BaseData.Rotate.Y, bone.BaseData.Rotate.Z, bone.BaseData.Rotate.W],
            BaseTranslation = [bone.BaseData.Translate.X, bone.BaseData.Translate.Y, bone.BaseData.Translate.Z],
        };
        foreach (AnimCurve curve in bone.Curves)
        {
            int columns = curve.Keys.GetLength(1);
            var keys = new float[curve.Keys.GetLength(0)][];
            for (int row = 0; row < keys.Length; row++)
            {
                keys[row] = new float[columns];
                for (int column = 0; column < columns; column++)
                    keys[row][column] = curve.Keys[row, column];
            }
            boneDump.Curves.Add(new AnimationCurveDump
            {
                DataOffset = curve.AnimDataOffset,
                Type = curve.CurveType.ToString(),
                StartFrame = curve.StartFrame,
                EndFrame = curve.EndFrame,
                Scale = curve.Scale,
                Offset = (float)curve.Offset,
                Delta = curve.Delta,
                Frames = curve.Frames,
                Keys = keys,
            });
        }
        dump.Bones.Add(boneDump);
    }
    Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
    File.WriteAllText(
        outputPath,
        JsonSerializer.Serialize(dump, new JsonSerializerOptions { WriteIndented = true }) + "\n",
        new UTF8Encoding(false));
    Console.WriteLine($"Dumped {animation.Name} from {inputAnimationPath} to {outputPath}");
    return 0;
}

if (args.Length >= 4 && args[0] == "--material-catalog")
{
    string outputPath = Path.GetFullPath(args[1]);
    string repositoryRoot = Path.GetFullPath(args[2]);
    string[] inputPaths = args.Skip(3).Select(Path.GetFullPath).ToArray();
    JsonObject materialCatalog = CreateMaterialCatalog(repositoryRoot, inputPaths);
    Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
    var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
    File.WriteAllText(
        outputPath,
        materialCatalog.ToJsonString(jsonOptions) + "\n",
        new UTF8Encoding(false));
    Console.WriteLine($"Cataloged material state from {inputPaths.Length} BFRES file(s) to {outputPath}");
    return 0;
}

if (args.Length >= 4 && args[0] == "--geometry-pack")
{
    string exactGeometryOutputDirectory = Path.GetFullPath(args[1]);
    string repositoryRoot = Path.GetFullPath(args[2]);
    string[] inputPaths = args.Skip(3).Select(Path.GetFullPath).ToArray();
    JsonObject geometryManifest = CreateExactGeometryPack(exactGeometryOutputDirectory, repositoryRoot, inputPaths);
    Directory.CreateDirectory(exactGeometryOutputDirectory);
    string manifestPath = Path.Combine(exactGeometryOutputDirectory, "manifest.json");
    File.WriteAllText(
        manifestPath,
        geometryManifest.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n",
        new UTF8Encoding(false));
    Console.WriteLine($"Packed exact geometry from {inputPaths.Length} BFRES file(s) to {manifestPath}");
    return 0;
}

if (args.Length == 3 && args[0] == "--catalog-tree")
{
    string inputRoot = Path.GetFullPath(args[1]);
    string outputPath = Path.GetFullPath(args[2]);
    Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
    var jsonOptions = new JsonSerializerOptions { WriteIndented = false };
    using var output = new StreamWriter(outputPath, false, new UTF8Encoding(false));
    int succeeded = 0;
    int failed = 0;
    foreach (string path in Directory.EnumerateFiles(inputRoot, "*.bfres", SearchOption.AllDirectories)
        .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
    {
        try
        {
            using FileStream stream = File.OpenRead(path);
            var catalogResource = new ResFile(stream);
            var models = catalogResource.Models.Select(model => model.Name).ToArray();
            var shapes = catalogResource.Models.SelectMany(model => model.Shapes).Select(shape => shape.Name)
                .Distinct(StringComparer.Ordinal).ToArray();
            var materials = catalogResource.Models.SelectMany(model => model.Materials).Select(material => material.Name)
                .Distinct(StringComparer.Ordinal).ToArray();
            var textures = catalogResource.Models.SelectMany(model => model.Materials)
                .SelectMany(material => material.TextureRefs ?? [])
                .Distinct(StringComparer.Ordinal).ToArray();
            var shaders = catalogResource.Models.SelectMany(model => model.Materials)
                .SelectMany(material => new[]
                {
                    material.ShaderAssign?.ShaderArchiveName,
                    material.ShaderAssign?.ShadingModelName,
                })
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Cast<string>().Distinct(StringComparer.Ordinal).ToArray();
            output.WriteLine(JsonSerializer.Serialize(new
            {
                path,
                resource_name = catalogResource.Name,
                models,
                shapes,
                materials,
                textures,
                shaders,
                error = (string?)null,
            }, jsonOptions));
            succeeded++;
        }
        catch (Exception exception)
        {
            output.WriteLine(JsonSerializer.Serialize(new
            {
                path,
                resource_name = "",
                models = Array.Empty<string>(),
                shapes = Array.Empty<string>(),
                materials = Array.Empty<string>(),
                textures = Array.Empty<string>(),
                shaders = Array.Empty<string>(),
                error = exception.GetType().Name + ": " + exception.Message,
            }, jsonOptions));
            failed++;
        }
    }
    Console.WriteLine($"Cataloged {succeeded} BFRES file(s); {failed} failed; output {outputPath}");
    return failed == 0 ? 0 : 1;
}

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: bfres-exporter INPUT.bfres OUTPUT_DIRECTORY");
    Console.Error.WriteLine("       bfres-exporter --catalog-tree INPUT_DIRECTORY OUTPUT.jsonl");
    return 2;
}

string inputPath = Path.GetFullPath(args[0]);
string outputDirectory = Path.GetFullPath(args[1]);
Directory.CreateDirectory(outputDirectory);

using FileStream input = File.OpenRead(inputPath);
var resource = new ResFile(input);
var catalog = new ResourceCatalog
{
    Source = inputPath,
    ResourceName = resource.Name,
};

foreach (Model model in resource.Models)
{
    string modelName = SafeName(model.Name);
    string objPath = Path.Combine(outputDirectory, modelName + ".obj");
    using var writer = new StreamWriter(objPath, false, new UTF8Encoding(false));
    writer.WriteLine("# Recovered from Nintendo Switch BFRES vertex/index buffers");
    writer.WriteLine("# Source: " + inputPath.Replace('\\', '/'));
    writer.WriteLine("o " + modelName);

    int vertexBase = 1;
    int texcoordBase = 1;
    int normalBase = 1;
    var modelInfo = new ModelCatalog { Name = model.Name };
    var namedTexcoordShapes = new List<NamedTexcoordShape>();
    bool hasMultipleTexcoordChannels = false;
    foreach (Shape shape in model.Shapes)
    {
        VertexBuffer vertexBuffer = model.VertexBuffers[shape.VertexBufferIndex];
        var helper = new VertexBufferHelper(vertexBuffer);
        var positions = helper.Attributes.FirstOrDefault(attribute => attribute.Name == "_p0")?.Data;
        var normals = helper.Attributes.FirstOrDefault(attribute => attribute.Name == "_n0")?.Data;
        var skinIndices = helper.Attributes.FirstOrDefault(attribute => attribute.Name == "_i0")?.Data;
        var skinWeights = helper.Attributes.FirstOrDefault(attribute => attribute.Name == "_w0")?.Data;
        var namedTexcoords = helper.Attributes
            .Where(attribute => attribute.Name.StartsWith("_u", StringComparison.Ordinal))
            .OrderBy(attribute => attribute.Name, StringComparer.Ordinal)
            .ToArray();
        hasMultipleTexcoordChannels |= namedTexcoords.Length > 1;
        string? texcoordAttribute = SelectTexcoordAttribute(model, shape, helper);
        var texcoords = helper.Attributes.FirstOrDefault(attribute => attribute.Name == texcoordAttribute)?.Data;
        if (positions is null)
            continue;

        var texcoordChannels = new SortedDictionary<string, float[][]>(StringComparer.Ordinal);
        foreach (var attribute in namedTexcoords)
        {
            texcoordChannels.Add(
                attribute.Name,
                attribute.Data.Select(uv => new[] { uv.X, 1.0f - uv.Y }).ToArray());
        }
        namedTexcoordShapes.Add(new NamedTexcoordShape
        {
            Group = SafeName(shape.Name),
            VertexOffset = vertexBase - 1,
            VertexCount = positions.Length,
            ObjChannel = texcoordAttribute,
            Channels = texcoordChannels,
        });

        writer.WriteLine("g " + SafeName(shape.Name));
        foreach (var p in positions)
            writer.WriteLine(FormattableString.Invariant($"v {p.X:R} {p.Y:R} {p.Z:R}"));
        if (texcoords is not null)
            foreach (var uv in texcoords)
                writer.WriteLine(FormattableString.Invariant($"vt {uv.X:R} {1.0f - uv.Y:R}"));
        if (normals is not null)
            foreach (var n in normals)
                writer.WriteLine(FormattableString.Invariant($"vn {n.X:R} {n.Y:R} {n.Z:R}"));

        uint[] indices = shape.Meshes.Count == 0 ? [] : shape.Meshes[0].GetIndices().ToArray();
        for (int i = 0; i + 2 < indices.Length; i += 3)
        {
            int a = checked((int)indices[i] + vertexBase);
            int b = checked((int)indices[i + 1] + vertexBase);
            int c = checked((int)indices[i + 2] + vertexBase);
            if (texcoords is not null && normals is not null)
            {
                int ta = checked((int)indices[i] + texcoordBase);
                int tb = checked((int)indices[i + 1] + texcoordBase);
                int tc = checked((int)indices[i + 2] + texcoordBase);
                int na = checked((int)indices[i] + normalBase);
                int nb = checked((int)indices[i + 1] + normalBase);
                int nc = checked((int)indices[i + 2] + normalBase);
                writer.WriteLine($"f {a}/{ta}/{na} {b}/{tb}/{nb} {c}/{tc}/{nc}");
            }
            else if (texcoords is not null)
            {
                int ta = checked((int)indices[i] + texcoordBase);
                int tb = checked((int)indices[i + 1] + texcoordBase);
                int tc = checked((int)indices[i + 2] + texcoordBase);
                writer.WriteLine($"f {a}/{ta} {b}/{tb} {c}/{tc}");
            }
            else if (normals is not null)
            {
                int na = checked((int)indices[i] + normalBase);
                int nb = checked((int)indices[i + 1] + normalBase);
                int nc = checked((int)indices[i + 2] + normalBase);
                writer.WriteLine($"f {a}//{na} {b}//{nb} {c}//{nc}");
            }
            else
                writer.WriteLine($"f {a} {b} {c}");
        }

        modelInfo.Shapes.Add(new ShapeCatalog
        {
            Name = shape.Name,
            MaterialIndex = shape.MaterialIndex,
            BoneIndex = shape.BoneIndex,
            VertexSkinCount = shape.VertexSkinCount,
            VertexCount = positions.Length,
            VertexOffset = vertexBase - 1,
            IndexCount = indices.Length,
            Attributes = helper.Attributes.Select(attribute => attribute.Name).ToArray(),
            TexcoordAttribute = texcoordAttribute,
            SkinIndices = skinIndices?.Select(value => new[] { value.X, value.Y, value.Z, value.W }).ToArray() ?? [],
            SkinWeights = skinWeights?.Select(value => new[] { value.X, value.Y, value.Z, value.W }).ToArray() ?? [],
        });
        vertexBase += positions.Length;
        if (texcoords is not null)
            texcoordBase += texcoords.Length;
        if (normals is not null)
            normalBase += normals.Length;
    }

    // OBJ has only one texture-coordinate index per face corner.  Preserve
    // the legacy selected channel in the OBJ, but emit every authored BFRES
    // UV channel when a model needs more than one.  The explicit sidecar lets
    // consumers bind different material samplers to _u0/_u2 without custom
    // OBJ syntax or a lossy channel choice.
    if (hasMultipleTexcoordChannels)
    {
        var texcoordSidecar = new NamedTexcoordSidecar
        {
            SchemaVersion = 1,
            Model = model.Name,
            VertexIndexing = "obj_position_zero_based",
            CoordinateConvention = "u_bfres_x__v_one_minus_bfres_y",
            VertexCount = vertexBase - 1,
            Shapes = namedTexcoordShapes,
        };
        File.WriteAllText(
            Path.Combine(outputDirectory, modelName + ".texcoords.json"),
            JsonSerializer.Serialize(texcoordSidecar) + "\n",
            new UTF8Encoding(false));
    }

    foreach (Material material in model.Materials)
    {
        modelInfo.Materials.Add(new MaterialCatalog
        {
            Name = material.Name,
            ShaderArchive = material.ShaderAssign?.ShaderArchiveName,
            ShadingModel = material.ShaderAssign?.ShadingModelName,
            TextureRefs = material.TextureRefs?.ToArray() ?? [],
            Samplers = material.Samplers?.Select(sampler => sampler.Name).ToArray() ?? [],
            ShaderParams = material.ShaderParams?.Select(parameter => parameter.Name).ToArray() ?? [],
            RenderInfos = material.RenderInfos?.Select(info => info.Name).ToArray() ?? [],
        });
    }

    modelInfo.SkeletonRotationMode = model.Skeleton.FlagsRotation.ToString();
    modelInfo.SkeletonScaleMode = model.Skeleton.FlagsScaling.ToString();
    modelInfo.MatrixToBoneList = model.Skeleton.MatrixToBoneList?.ToArray() ?? [];
    modelInfo.InverseModelMatrices = (model.Skeleton.InverseModelMatrices ?? []).Select(matrix => new[]
    {
        matrix.M11, matrix.M12, matrix.M13, matrix.M14,
        matrix.M21, matrix.M22, matrix.M23, matrix.M24,
        matrix.M31, matrix.M32, matrix.M33, matrix.M34,
    }).ToArray();
    foreach (Bone bone in model.Skeleton.Bones)
    {
        modelInfo.Bones.Add(new BoneCatalog
        {
            Name = bone.Name,
            ParentIndex = bone.ParentIndex,
            Position = [bone.Position.X, bone.Position.Y, bone.Position.Z],
            Rotation = [bone.Rotation.X, bone.Rotation.Y, bone.Rotation.Z, bone.Rotation.W],
            Scale = [bone.Scale.X, bone.Scale.Y, bone.Scale.Z],
            SmoothMatrixIndex = bone.SmoothMatrixIndex,
            RigidMatrixIndex = bone.RigidMatrixIndex,
            RotationMode = bone.FlagsRotation.ToString(),
        });
    }
    catalog.Models.Add(modelInfo);
}

var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(Path.Combine(outputDirectory, "bfres.json"), JsonSerializer.Serialize(catalog, options), new UTF8Encoding(false));
Console.WriteLine($"Exported {catalog.Models.Count} model(s) from {inputPath} to {outputDirectory}");
return 0;

static string SafeName(string? value)
{
    value = string.IsNullOrWhiteSpace(value) ? "unnamed" : value;
    var invalid = Path.GetInvalidFileNameChars().ToHashSet();
    return new string(value.Select(c => invalid.Contains(c) || char.IsWhiteSpace(c) ? '_' : c).ToArray());
}

static JsonObject CreateExactGeometryPack(
    string outputDirectory,
    string repositoryRoot,
    IReadOnlyList<string> inputPaths)
{
    if (!Directory.Exists(repositoryRoot))
        throw new DirectoryNotFoundException($"Repository root does not exist: {repositoryRoot}");
    if (inputPaths.Count == 0)
        throw new ArgumentException("At least one BFRES input is required.");

    Directory.CreateDirectory(outputDirectory);
    var resourceRecords = new JsonArray();
    int rawVertexStreamCount = 0;
    int rawIndexStreamCount = 0;
    int canonicalIndexStreamCount = 0;
    foreach (string inputPath in inputPaths)
    {
        byte[] sourceBytes = File.ReadAllBytes(inputPath);
        using var source = new MemoryStream(sourceBytes, writable: false);
        var resource = new ResFile(source);
        string resourceDirectoryName = SafeName(resource.Name);
        string resourceDirectory = Path.Combine(outputDirectory, resourceDirectoryName);
        Directory.CreateDirectory(resourceDirectory);

        var modelRecords = new JsonArray();
        for (int modelIndex = 0; modelIndex < resource.Models.Count; modelIndex++)
        {
            Model model = resource.Models[modelIndex];
            string modelDirectoryName = $"model_{modelIndex:D2}_{SafeName(model.Name)}";
            string modelDirectory = Path.Combine(resourceDirectory, modelDirectoryName);
            Directory.CreateDirectory(modelDirectory);

            var vertexBufferRecords = new JsonArray();
            for (int vertexBufferIndex = 0; vertexBufferIndex < model.VertexBuffers.Count; vertexBufferIndex++)
            {
                VertexBuffer vertexBuffer = model.VertexBuffers[vertexBufferIndex];
                var helper = new VertexBufferHelper(vertexBuffer);
                int vertexCount = helper.Attributes.Count == 0
                    ? 0
                    : helper.Attributes.Max(attribute => attribute.Data.Length);
                var streamRecords = new JsonArray();
                for (int streamIndex = 0; streamIndex < vertexBuffer.Buffers.Count; streamIndex++)
                {
                    byte[] streamBytes = vertexBuffer.Buffers[streamIndex].Data ?? Array.Empty<byte>();
                    string fileName = $"vertex_buffer_{vertexBufferIndex:D2}_stream_{streamIndex:D2}.bin";
                    string absolutePath = Path.Combine(modelDirectory, fileName);
                    File.WriteAllBytes(absolutePath, streamBytes);
                    int stride = streamIndex < vertexBuffer.StrideArray.Count
                        ? checked((int)vertexBuffer.StrideArray[streamIndex].Stride)
                        : vertexBuffer.Buffers[streamIndex].Stride;
                    streamRecords.Add(new JsonObject
                    {
                        ["stream_index"] = streamIndex,
                        ["path"] = RelativeSlashPath(repositoryRoot, absolutePath),
                        ["byte_length"] = streamBytes.LongLength,
                        ["sha256"] = Sha256Hex(streamBytes),
                        ["stride"] = stride,
                        ["stored_buffer_size"] = vertexBuffer.Buffers[streamIndex].buffSize,
                        ["stored_data_offset"] = vertexBuffer.Buffers[streamIndex].DataOffset,
                    });
                    rawVertexStreamCount++;
                }

                var attributeRecords = new JsonArray();
                foreach (VertexAttrib attribute in vertexBuffer.Attributes)
                {
                    attributeRecords.Add(new JsonObject
                    {
                        ["name"] = attribute.Name,
                        ["buffer_index"] = attribute.BufferIndex,
                        ["byte_offset"] = attribute.Offset,
                        ["format"] = attribute.Format.ToString(),
                        ["format_value"] = Convert.ToInt64(attribute.Format, CultureInfo.InvariantCulture),
                    });
                }

                vertexBufferRecords.Add(new JsonObject
                {
                    ["vertex_buffer_index"] = vertexBufferIndex,
                    ["vertex_count"] = vertexCount,
                    ["vertex_skin_count"] = vertexBuffer.VertexSkinCount,
                    ["streams"] = streamRecords,
                    ["attributes"] = attributeRecords,
                });
            }

            var shapeRecords = new JsonArray();
            for (int shapeIndex = 0; shapeIndex < model.Shapes.Count; shapeIndex++)
            {
                Shape shape = model.Shapes[shapeIndex];
                string? materialName = shape.MaterialIndex < model.Materials.Count
                    ? model.Materials[shape.MaterialIndex].Name
                    : null;
                var meshRecords = new JsonArray();
                for (int meshIndex = 0; meshIndex < shape.Meshes.Count; meshIndex++)
                {
                    Mesh mesh = shape.Meshes[meshIndex];
                    uint[] indices = mesh.GetIndices().ToArray();
                    (byte[] rawIndexBytes, long rawIndexSourceOffset) = ExtractExactRawMeshIndexBytes(
                        sourceBytes,
                        BufferInfo.BufferOffset,
                        mesh,
                        indices);
                    byte[] canonicalIndices = new byte[checked(indices.Length * sizeof(uint))];
                    for (int index = 0; index < indices.Length; index++)
                        BinaryPrimitives.WriteUInt32LittleEndian(canonicalIndices.AsSpan(index * sizeof(uint)), indices[index]);

                    string stem = $"shape_{shapeIndex:D2}_{SafeName(shape.Name)}_mesh_{meshIndex:D2}";
                    string rawFileName = stem + ".indices.raw.bin";
                    string canonicalFileName = stem + ".indices.u32le.bin";
                    string rawPath = Path.Combine(modelDirectory, rawFileName);
                    string canonicalPath = Path.Combine(modelDirectory, canonicalFileName);
                    File.WriteAllBytes(rawPath, rawIndexBytes);
                    File.WriteAllBytes(canonicalPath, canonicalIndices);
                    rawIndexStreamCount++;
                    canonicalIndexStreamCount++;

                    meshRecords.Add(new JsonObject
                    {
                        ["mesh_index"] = meshIndex,
                        ["primitive_type"] = mesh.PrimitiveType.ToString(),
                        ["primitive_type_value"] = Convert.ToInt64(mesh.PrimitiveType, CultureInfo.InvariantCulture),
                        ["index_format"] = mesh.IndexFormat.ToString(),
                        ["index_format_value"] = Convert.ToInt64(mesh.IndexFormat, CultureInfo.InvariantCulture),
                        ["index_count"] = indices.LongLength,
                        ["first_vertex"] = mesh.FirstVertex,
                        ["raw_index_stream"] = ExactFileRecord(repositoryRoot, rawPath, rawIndexBytes),
                        ["raw_index_source_file_offset"] = rawIndexSourceOffset,
                        ["canonical_uint32_index_stream"] = ExactFileRecord(repositoryRoot, canonicalPath, canonicalIndices),
                    });
                }

                shapeRecords.Add(new JsonObject
                {
                    ["shape_index"] = shapeIndex,
                    ["name"] = shape.Name,
                    ["material_index"] = shape.MaterialIndex,
                    ["material_name"] = materialName,
                    ["bone_index"] = shape.BoneIndex,
                    ["vertex_buffer_index"] = shape.VertexBufferIndex,
                    ["vertex_skin_count"] = shape.VertexSkinCount,
                    ["meshes"] = meshRecords,
                });
            }

            modelRecords.Add(new JsonObject
            {
                ["model_index"] = modelIndex,
                ["name"] = model.Name,
                ["vertex_buffers"] = vertexBufferRecords,
                ["shapes"] = shapeRecords,
            });
        }

        resourceRecords.Add(new JsonObject
        {
            ["source"] = RelativeSlashPath(repositoryRoot, inputPath),
            ["resource_name"] = resource.Name,
            ["byte_length"] = sourceBytes.LongLength,
            ["sha256"] = Sha256Hex(sourceBytes),
            ["models"] = modelRecords,
        });
    }

    return new JsonObject
    {
        ["schema_version"] = 1,
        ["description"] = "Byte-exact BFRES vertex/index streams and complete attribute layouts for direct title-shader execution.",
        ["generator"] = "tools/bfres-exporter --geometry-pack",
        ["storage_contract"] = new JsonObject
        {
            ["vertex_streams"] = "byte-for-byte VertexBuffer.buffData.Data from BFRES; no OBJ conversion or attribute reconstruction",
            ["raw_index_streams"] = "byte-for-byte private Mesh.Data loaded by Syroot.NintenTools.NSW.Bfres",
            ["canonical_index_streams"] = "decoded BFRES index values serialized uint32 little-endian for portable indexed draws",
        },
        ["totals"] = new JsonObject
        {
            ["resource_count"] = inputPaths.Count,
            ["raw_vertex_stream_count"] = rawVertexStreamCount,
            ["raw_index_stream_count"] = rawIndexStreamCount,
            ["canonical_index_stream_count"] = canonicalIndexStreamCount,
        },
        ["resources"] = resourceRecords,
    };
}

static (byte[] Bytes, long SourceFileOffset) ExtractExactRawMeshIndexBytes(
    byte[] sourceBytes,
    long bufferBaseOffset,
    Mesh mesh,
    IReadOnlyList<uint> decodedIndices)
{
    int elementSize = mesh.IndexFormat switch
    {
        Syroot.NintenTools.NSW.Bfres.GFX.IndexFormat.UnsignedByte => sizeof(byte),
        Syroot.NintenTools.NSW.Bfres.GFX.IndexFormat.UInt16 => sizeof(ushort),
        Syroot.NintenTools.NSW.Bfres.GFX.IndexFormat.UInt32 => sizeof(uint),
        _ => throw new InvalidDataException($"Unsupported BFRES index format {mesh.IndexFormat}."),
    };
    byte[] expected = new byte[checked(decodedIndices.Count * elementSize)];
    for (int index = 0; index < decodedIndices.Count; index++)
    {
        uint decodedValue = decodedIndices[index];
        int byteOffset = checked(index * elementSize);
        switch (elementSize)
        {
            case sizeof(byte):
                expected[byteOffset] = checked((byte)decodedValue);
                break;
            case sizeof(ushort):
                BinaryPrimitives.WriteUInt16LittleEndian(expected.AsSpan(byteOffset), checked((ushort)decodedValue));
                break;
            case sizeof(uint):
                BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(byteOffset), decodedValue);
                break;
        }
    }

    FieldInfo? offsetField = typeof(Mesh).GetField(
        "DataOffset",
        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
    long storedOffset = offsetField?.GetValue(mesh) is long storedDataOffsetValue ? storedDataOffsetValue : -1;
    foreach (long candidate in new[] { storedOffset, checked(bufferBaseOffset + storedOffset) }.Distinct())
    {
        if (candidate < 0 || candidate + expected.LongLength > sourceBytes.LongLength)
            continue;
        if (sourceBytes.AsSpan(checked((int)candidate), expected.Length).SequenceEqual(expected))
            return (sourceBytes.AsSpan(checked((int)candidate), expected.Length).ToArray(), candidate);
    }

    int firstMatch = sourceBytes.AsSpan().IndexOf(expected);
    if (firstMatch >= 0)
    {
        int nextStart = checked(firstMatch + 1);
        int secondRelative = sourceBytes.AsSpan(nextStart).IndexOf(expected);
        if (secondRelative < 0)
            return (sourceBytes.AsSpan(firstMatch, expected.Length).ToArray(), firstMatch);
    }
    throw new InvalidDataException(
        $"Could not locate a unique source-backed {mesh.IndexFormat} index stream of {decodedIndices.Count} values; " +
        $"stored data offset={storedOffset}, buffer base offset={bufferBaseOffset}; " +
        "refusing to substitute reconstructed index bytes.");
}

static JsonObject ExactFileRecord(string repositoryRoot, string absolutePath, byte[] bytes)
{
    return new JsonObject
    {
        ["path"] = RelativeSlashPath(repositoryRoot, absolutePath),
        ["byte_length"] = bytes.LongLength,
        ["sha256"] = Sha256Hex(bytes),
    };
}

static string RelativeSlashPath(string repositoryRoot, string absolutePath)
{
    return Path.GetRelativePath(repositoryRoot, absolutePath).Replace('\\', '/');
}

static string Sha256Hex(ReadOnlySpan<byte> bytes)
{
    return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}

static string? SelectTexcoordAttribute(Model model, Shape shape, VertexBufferHelper helper)
{
    var available = helper.Attributes.Select(attribute => attribute.Name)
        .Where(name => name.StartsWith("_u", StringComparison.Ordinal))
        .ToHashSet(StringComparer.Ordinal);
    if (available.Count == 0)
        return null;

    if (shape.MaterialIndex < model.Materials.Count)
    {
        ShaderAssign? shaderAssign = model.Materials[shape.MaterialIndex].ShaderAssign;
        int optionCount = Math.Min(shaderAssign?.ShaderOptionDict?.Count ?? 0, shaderAssign?.ShaderOptions?.Count ?? 0);
        for (int index = 0; index < optionCount; index++)
        {
            string optionName = shaderAssign!.ShaderOptionDict.GetKey(index);
            string optionValue = shaderAssign.ShaderOptions[index];
            if (!optionName.StartsWith("tex_coord", StringComparison.Ordinal) ||
                !optionName.EndsWith("_vtx", StringComparison.Ordinal) ||
                !int.TryParse(optionValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out int vertexTexcoordIndex))
                continue;
            string selected = $"_u{vertexTexcoordIndex}";
            if (available.Contains(selected))
                return selected;
        }
    }

    if (available.Contains("_u0"))
        return "_u0";
    return available.OrderBy(name => name, StringComparer.Ordinal).First();
}

static JsonObject CreateMaterialCatalog(string repositoryRoot, IReadOnlyList<string> inputPaths)
{
    if (!Directory.Exists(repositoryRoot))
        throw new DirectoryNotFoundException($"Repository root does not exist: {repositoryRoot}");
    if (inputPaths.Count == 0)
        throw new ArgumentException("At least one BFRES input is required.");

    var totals = new MaterialCatalogTotals();
    var uniqueTextureNames = new HashSet<string>(StringComparer.Ordinal);
    var resources = new JsonArray();
    foreach (string inputPath in inputPaths)
    {
        if (!File.Exists(inputPath))
            throw new FileNotFoundException("BFRES input does not exist.", inputPath);

        byte[] sourceBytes = File.ReadAllBytes(inputPath);
        using var stream = new MemoryStream(sourceBytes, writable: false);
        var resource = new ResFile(stream);
        totals.ResourceCount++;
        totals.SourceByteCount += sourceBytes.LongLength;

        var models = new JsonArray();
        for (int modelIndex = 0; modelIndex < resource.Models.Count; modelIndex++)
        {
            Model model = resource.Models[modelIndex];
            totals.ModelCount++;

            var shapes = new JsonArray();
            for (int shapeIndex = 0; shapeIndex < model.Shapes.Count; shapeIndex++)
            {
                Shape shape = model.Shapes[shapeIndex];
                VertexBuffer vertexBuffer = model.VertexBuffers[shape.VertexBufferIndex];
                var vertexHelper = new VertexBufferHelper(vertexBuffer);
                int vertexCount = vertexHelper.Attributes.FirstOrDefault(attribute => attribute.Name == "_p0")?.Data.Length ?? 0;
                string? texcoordAttribute = SelectTexcoordAttribute(model, shape, vertexHelper);
                int indexCount = shape.Meshes.Sum(mesh => mesh.GetIndices().Count());
                string? materialName = shape.MaterialIndex < model.Materials.Count
                    ? model.Materials[shape.MaterialIndex].Name
                    : null;
                shapes.Add(new JsonObject
                {
                    ["index"] = shapeIndex,
                    ["name"] = shape.Name,
                    ["material_index"] = shape.MaterialIndex,
                    ["material_name"] = materialName,
                    ["bone_index"] = shape.BoneIndex,
                    ["vertex_buffer_index"] = shape.VertexBufferIndex,
                    ["vertex_skin_count"] = shape.VertexSkinCount,
                    ["vertex_count"] = vertexCount,
                    ["mesh_count"] = shape.Meshes.Count,
                    ["index_count"] = indexCount,
                    ["attributes"] = StringArray(vertexHelper.Attributes.Select(attribute => attribute.Name)),
                    ["texcoord_attribute"] = texcoordAttribute,
                });
                totals.ShapeCount++;
            }

            var materials = new JsonArray();
            for (int materialIndex = 0; materialIndex < model.Materials.Count; materialIndex++)
            {
                Material material = model.Materials[materialIndex];
                ShaderAssign shaderAssign = material.ShaderAssign ?? new ShaderAssign();
                ResDict samplerDict = material.SamplerDict ?? new ResDict();
                IList<Sampler> materialSamplers = material.Samplers ?? Array.Empty<Sampler>();
                IList<string> textureRefs = material.TextureRefs ?? Array.Empty<string>();
                ResDict attributeAssignDict = shaderAssign.AttribAssignDict ?? new ResDict();
                IList<string> attributeAssignValues = shaderAssign.AttribAssigns ?? Array.Empty<string>();
                ResDict samplerAssignDict = shaderAssign.SamplerAssignDict ?? new ResDict();
                IList<string> samplerAssignValues = shaderAssign.SamplerAssigns ?? Array.Empty<string>();
                ResDict shaderOptionDict = shaderAssign.ShaderOptionDict ?? new ResDict();
                IList<string> shaderOptionValues = shaderAssign.ShaderOptions ?? Array.Empty<string>();
                ResDict shaderParamDict = material.ShaderParamDict ?? new ResDict();
                IList<ShaderParam> shaderParamValues = material.ShaderParams ?? Array.Empty<ShaderParam>();
                byte[] shaderParamData = material.ShaderParamData ?? Array.Empty<byte>();
                ResDict renderInfoDict = material.RenderInfoDict ?? new ResDict();
                IList<RenderInfo> renderInfoValues = material.RenderInfos is null
                    ? Array.Empty<RenderInfo>()
                    : material.RenderInfos;
                totals.MaterialCount++;

                string[] samplerNames = Enumerable.Range(0, samplerDict.Count)
                    .Select(index => samplerDict.GetKey(index)).ToArray();

                var attributeAssignments = new JsonArray();
                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} attribute assignments",
                    attributeAssignDict.Count,
                    attributeAssignValues.Count);
                for (int index = 0; index < attributeAssignValues.Count; index++)
                {
                    attributeAssignments.Add(new JsonObject
                    {
                        ["shader_attribute"] = attributeAssignDict.GetKey(index),
                        ["vertex_attribute"] = attributeAssignValues[index],
                    });
                    totals.AttributeAssignmentCount++;
                }

                var samplerAssignments = new JsonArray();
                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} sampler assignments",
                    samplerAssignDict.Count,
                    samplerAssignValues.Count);
                for (int index = 0; index < samplerAssignValues.Count; index++)
                {
                    string materialSampler = samplerAssignValues[index];
                    int materialSamplerIndex = Array.FindIndex(
                        samplerNames,
                        name => string.Equals(name, materialSampler, StringComparison.Ordinal));
                    samplerAssignments.Add(new JsonObject
                    {
                        ["shader_sampler"] = samplerAssignDict.GetKey(index),
                        ["material_sampler"] = materialSampler,
                        ["material_sampler_index"] = materialSamplerIndex >= 0 ? materialSamplerIndex : null,
                        ["texture_ref"] = materialSamplerIndex >= 0 && materialSamplerIndex < textureRefs.Count
                            ? textureRefs[materialSamplerIndex]
                            : null,
                    });
                    totals.SamplerAssignmentCount++;
                }

                var shaderOptions = new JsonArray();
                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} shader options",
                    shaderOptionDict.Count,
                    shaderOptionValues.Count);
                for (int index = 0; index < shaderOptionValues.Count; index++)
                {
                    shaderOptions.Add(new JsonObject
                    {
                        ["name"] = shaderOptionDict.GetKey(index),
                        ["value"] = shaderOptionValues[index],
                    });
                    totals.ShaderOptionCount++;
                }

                var textureAssignments = new JsonArray();
                for (int index = 0; index < textureRefs.Count; index++)
                {
                    string textureRef = textureRefs[index];
                    uniqueTextureNames.Add(textureRef);
                    string? materialSampler = index < samplerNames.Length ? samplerNames[index] : null;
                    var shaderSamplers = new JsonArray();
                    if (materialSampler is not null)
                    {
                        for (int assignIndex = 0; assignIndex < samplerAssignValues.Count; assignIndex++)
                        {
                            if (string.Equals(samplerAssignValues[assignIndex], materialSampler, StringComparison.Ordinal))
                                shaderSamplers.Add(samplerAssignDict.GetKey(assignIndex));
                        }
                    }
                    textureAssignments.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["texture_ref"] = textureRef,
                        ["material_sampler"] = materialSampler,
                        ["sampler_state_index"] = index < materialSamplers.Count ? index : null,
                        ["shader_samplers"] = shaderSamplers,
                    });
                    totals.TextureAssignmentCount++;
                }

                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} material samplers",
                    samplerDict.Count,
                    materialSamplers.Count);
                var samplers = new JsonArray();
                for (int index = 0; index < materialSamplers.Count; index++)
                {
                    Sampler sampler = materialSamplers[index];
                    samplers.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["name"] = samplerNames[index],
                        ["stored_name"] = sampler.Name,
                        ["texture_ref"] = index < textureRefs.Count ? textureRefs[index] : null,
                        ["wrap_u"] = sampler.WrapModeU.ToString(),
                        ["wrap_u_value"] = Convert.ToInt32(sampler.WrapModeU, CultureInfo.InvariantCulture),
                        ["wrap_v"] = sampler.WrapModeV.ToString(),
                        ["wrap_v_value"] = Convert.ToInt32(sampler.WrapModeV, CultureInfo.InvariantCulture),
                        ["wrap_w"] = sampler.WrapModeW.ToString(),
                        ["wrap_w_value"] = Convert.ToInt32(sampler.WrapModeW, CultureInfo.InvariantCulture),
                        ["compare_function"] = sampler.CompareFunc.ToString(),
                        ["compare_function_value"] = Convert.ToInt32(sampler.CompareFunc, CultureInfo.InvariantCulture),
                        ["border_color"] = sampler.BorderColorType.ToString(),
                        ["border_color_value"] = Convert.ToInt32(sampler.BorderColorType, CultureInfo.InvariantCulture),
                        ["max_anisotropic"] = sampler.MaxAnisotropic.ToString(),
                        ["max_anisotropic_value"] = Convert.ToInt32(sampler.MaxAnisotropic, CultureInfo.InvariantCulture),
                        ["shrink_filter"] = sampler.ShrinkXY.ToString(),
                        ["shrink_filter_value"] = Convert.ToInt32(sampler.ShrinkXY, CultureInfo.InvariantCulture),
                        ["expand_filter"] = sampler.ExpandXY.ToString(),
                        ["expand_filter_value"] = Convert.ToInt32(sampler.ExpandXY, CultureInfo.InvariantCulture),
                        ["mipmap_filter"] = sampler.Mipmap.ToString(),
                        ["mipmap_filter_value"] = Convert.ToInt32(sampler.Mipmap, CultureInfo.InvariantCulture),
                        ["min_lod"] = sampler.MinLOD,
                        ["max_lod"] = sampler.MaxLOD,
                        ["lod_bias"] = sampler.LODBias,
                    });
                    totals.SamplerStateCount++;
                }

                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} shader parameters",
                    shaderParamDict.Count,
                    shaderParamValues.Count);
                var shaderParameters = new JsonArray();
                for (int index = 0; index < shaderParamValues.Count; index++)
                {
                    ShaderParam parameter = shaderParamValues[index];
                    int dataOffset = parameter.DataOffset;
                    int dataSize = checked((int)parameter.DataSize);
                    if (dataOffset < 0 || dataOffset + dataSize > shaderParamData.Length)
                    {
                        throw new InvalidDataException(
                            $"Shader parameter {resource.Name}/{model.Name}/{material.Name}/{parameter.Name} " +
                            $"references [{dataOffset}, {dataOffset + dataSize}) outside {shaderParamData.Length} bytes.");
                    }
                    ReadOnlySpan<byte> valueBytes = shaderParamData.AsSpan(dataOffset, dataSize);
                    string dictionaryName = shaderParamDict.GetKey(index);
                    shaderParameters.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["name"] = string.IsNullOrEmpty(parameter.Name) ? dictionaryName : parameter.Name,
                        ["dictionary_name"] = dictionaryName,
                        ["type"] = parameter.Type.ToString(),
                        ["type_value"] = Convert.ToInt32(parameter.Type, CultureInfo.InvariantCulture),
                        ["data_offset"] = dataOffset,
                        ["data_size"] = dataSize,
                        ["depended_index"] = parameter.DependedIndex,
                        ["depend_index"] = parameter.DependIndex,
                        ["volatile"] = IsVolatile(material.VolatileFlags, index),
                        ["static_value"] = DecodeShaderParameter(parameter.Type, valueBytes),
                        ["raw_hex"] = Convert.ToHexString(valueBytes).ToLowerInvariant(),
                    });
                    totals.ShaderParameterCount++;
                }

                RequireMatchingCount(
                    $"{resource.Name}/{model.Name}/{material.Name} render infos",
                    renderInfoDict.Count,
                    renderInfoValues.Count);
                var renderInfos = new JsonArray();
                for (int index = 0; index < renderInfoValues.Count; index++)
                {
                    RenderInfo info = renderInfoValues[index];
                    string dictionaryName = renderInfoDict.GetKey(index);
                    renderInfos.Add(new JsonObject
                    {
                        ["index"] = index,
                        ["name"] = string.IsNullOrEmpty(info.Name) ? dictionaryName : info.Name,
                        ["dictionary_name"] = dictionaryName,
                        ["type"] = info.Type.ToString(),
                        ["type_value"] = Convert.ToInt32(info.Type, CultureInfo.InvariantCulture),
                        ["value"] = DecodeRenderInfo(info),
                    });
                    totals.RenderInfoCount++;
                }

                materials.Add(new JsonObject
                {
                    ["index"] = materialIndex,
                    ["name"] = material.Name,
                    ["flags"] = material.Flags.ToString(),
                    ["flags_value"] = Convert.ToInt64(material.Flags, CultureInfo.InvariantCulture),
                    ["shader_archive"] = shaderAssign.ShaderArchiveName,
                    ["shading_model"] = shaderAssign.ShadingModelName,
                    ["shader_revision"] = shaderAssign.Revision,
                    ["attribute_assignments"] = attributeAssignments,
                    ["sampler_assignments"] = samplerAssignments,
                    ["shader_options"] = shaderOptions,
                    ["texture_assignments"] = textureAssignments,
                    ["samplers"] = samplers,
                    ["shader_parameters"] = shaderParameters,
                    ["render_infos"] = renderInfos,
                });
            }

            models.Add(new JsonObject
            {
                ["index"] = modelIndex,
                ["name"] = model.Name,
                ["shapes"] = shapes,
                ["materials"] = materials,
            });
        }

        resources.Add(new JsonObject
        {
            ["source"] = Path.GetRelativePath(repositoryRoot, inputPath).Replace('\\', '/'),
            ["byte_length"] = sourceBytes.LongLength,
            ["sha256"] = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant(),
            ["resource_name"] = resource.Name,
            ["bfres_version"] = new JsonObject
            {
                ["major"] = resource.VersionMajor,
                ["major2"] = resource.VersionMajor2,
                ["minor"] = resource.VersionMinor,
                ["minor2"] = resource.VersionMinor2,
            },
            ["models"] = models,
        });
    }

    return new JsonObject
    {
        ["schema_version"] = 1,
        ["description"] = "Exact static material state recovered from the supplied BFRES resources.",
        ["generator"] = "tools/bfres-exporter --material-catalog",
        ["totals"] = new JsonObject
        {
            ["resource_count"] = totals.ResourceCount,
            ["source_byte_count"] = totals.SourceByteCount,
            ["model_count"] = totals.ModelCount,
            ["shape_count"] = totals.ShapeCount,
            ["material_count"] = totals.MaterialCount,
            ["texture_assignment_count"] = totals.TextureAssignmentCount,
            ["unique_texture_name_count"] = uniqueTextureNames.Count,
            ["sampler_state_count"] = totals.SamplerStateCount,
            ["attribute_assignment_count"] = totals.AttributeAssignmentCount,
            ["sampler_assignment_count"] = totals.SamplerAssignmentCount,
            ["shader_option_count"] = totals.ShaderOptionCount,
            ["shader_parameter_count"] = totals.ShaderParameterCount,
            ["render_info_count"] = totals.RenderInfoCount,
        },
        ["resources"] = resources,
    };
}

static JsonArray StringArray(IEnumerable<string> values)
{
    var result = new JsonArray();
    foreach (string value in values)
        result.Add(value);
    return result;
}

static JsonArray BoolArray(ReadOnlySpan<byte> bytes)
{
    var result = new JsonArray();
    for (int offset = 0; offset < bytes.Length; offset += sizeof(int))
        result.Add(BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]) != 0);
    return result;
}

static JsonArray IntArray(ReadOnlySpan<byte> bytes)
{
    var result = new JsonArray();
    for (int offset = 0; offset < bytes.Length; offset += sizeof(int))
        result.Add(BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]));
    return result;
}

static JsonArray UIntArray(ReadOnlySpan<byte> bytes)
{
    var result = new JsonArray();
    for (int offset = 0; offset < bytes.Length; offset += sizeof(uint))
        result.Add(BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]));
    return result;
}

static JsonArray FloatArray(ReadOnlySpan<byte> bytes)
{
    var result = new JsonArray();
    for (int offset = 0; offset < bytes.Length; offset += sizeof(float))
    {
        int bits = BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]);
        result.Add(BitConverter.Int32BitsToSingle(bits));
    }
    return result;
}

static float ReadFloat(ReadOnlySpan<byte> bytes, int offset)
{
    return BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(bytes[offset..]));
}

static JsonNode DecodeShaderParameter(ShaderParamType type, ReadOnlySpan<byte> bytes)
{
    int typeValue = (int)type;
    if (typeValue is >= 0 and <= 3)
        return BoolArray(bytes);
    if (typeValue is >= 4 and <= 7)
        return IntArray(bytes);
    if (typeValue is >= 8 and <= 11)
        return UIntArray(bytes);
    if (typeValue is >= 12 and <= 15 || typeValue is >= 17 and <= 19 || typeValue is >= 21 and <= 23 || typeValue is >= 25 and <= 27)
        return FloatArray(bytes);

    return type switch
    {
        ShaderParamType.Srt2D => new JsonObject
        {
            ["scaling"] = FloatArray(bytes[..8]),
            ["rotation"] = ReadFloat(bytes, 8),
            ["translation"] = FloatArray(bytes[12..20]),
        },
        ShaderParamType.Srt3D => new JsonObject
        {
            ["scaling"] = FloatArray(bytes[..12]),
            ["rotation"] = FloatArray(bytes[12..24]),
            ["translation"] = FloatArray(bytes[24..36]),
        },
        ShaderParamType.TexSrt => new JsonObject
        {
            ["mode"] = ((TexSrtMode)BinaryPrimitives.ReadInt32LittleEndian(bytes)).ToString(),
            ["mode_value"] = BinaryPrimitives.ReadInt32LittleEndian(bytes),
            ["scaling"] = FloatArray(bytes[4..12]),
            ["rotation"] = ReadFloat(bytes, 12),
            ["translation"] = FloatArray(bytes[16..24]),
        },
        ShaderParamType.TexSrtEx => new JsonObject
        {
            ["mode"] = ((TexSrtMode)BinaryPrimitives.ReadInt32LittleEndian(bytes)).ToString(),
            ["mode_value"] = BinaryPrimitives.ReadInt32LittleEndian(bytes),
            ["scaling"] = FloatArray(bytes[4..12]),
            ["rotation"] = ReadFloat(bytes, 12),
            ["translation"] = FloatArray(bytes[16..24]),
            ["matrix_pointer"] = BinaryPrimitives.ReadUInt32LittleEndian(bytes[24..]),
        },
        _ => new JsonObject
        {
            ["encoding"] = "raw_bytes",
            ["hex"] = Convert.ToHexString(bytes).ToLowerInvariant(),
        },
    };
}

static JsonArray DecodeRenderInfo(RenderInfo info)
{
    var result = new JsonArray();
    switch (info.Type)
    {
        case RenderInfoType.Int32:
            foreach (int value in info.GetValueInt32s())
                result.Add(value);
            break;
        case RenderInfoType.Single:
            foreach (float value in info.GetValueSingles())
                result.Add(value);
            break;
        case RenderInfoType.String:
            foreach (string value in info.GetValueStrings())
                result.Add(value);
            break;
        default:
            throw new InvalidDataException($"Unsupported render-info type {info.Type} for {info.Name}.");
    }
    return result;
}

static bool IsVolatile(byte[]? flags, int index)
{
    if (flags is null || index / 8 >= flags.Length)
        return false;
    return (flags[index / 8] & (1 << (index % 8))) != 0;
}

static void RequireMatchingCount(string label, int dictionaryCount, int valueCount)
{
    if (dictionaryCount != valueCount)
        throw new InvalidDataException($"{label}: dictionary has {dictionaryCount} names but payload has {valueCount} values.");
}

sealed class ResourceCatalog
{
    public string Source { get; set; } = "";
    public string ResourceName { get; set; } = "";
    public List<ModelCatalog> Models { get; } = [];
}

sealed class ModelCatalog
{
    public string Name { get; set; } = "";
    public List<ShapeCatalog> Shapes { get; } = [];
    public List<MaterialCatalog> Materials { get; } = [];
    public List<BoneCatalog> Bones { get; } = [];
    public string SkeletonRotationMode { get; set; } = "";
    public string SkeletonScaleMode { get; set; } = "";
    public ushort[] MatrixToBoneList { get; set; } = [];
    public float[][] InverseModelMatrices { get; set; } = [];
}

sealed class ShapeCatalog
{
    public string Name { get; set; } = "";
    public ushort MaterialIndex { get; set; }
    public ushort BoneIndex { get; set; }
    public byte VertexSkinCount { get; set; }
    public int VertexCount { get; set; }
    public int VertexOffset { get; set; }
    public int IndexCount { get; set; }
    public string[] Attributes { get; set; } = [];
    public string? TexcoordAttribute { get; set; }
    public float[][] SkinIndices { get; set; } = [];
    public float[][] SkinWeights { get; set; } = [];
}

sealed class NamedTexcoordSidecar
{
    public int SchemaVersion { get; set; }
    public string Model { get; set; } = "";
    public string VertexIndexing { get; set; } = "";
    public string CoordinateConvention { get; set; } = "";
    public int VertexCount { get; set; }
    public List<NamedTexcoordShape> Shapes { get; set; } = [];
}

sealed class NamedTexcoordShape
{
    public string Group { get; set; } = "";
    public int VertexOffset { get; set; }
    public int VertexCount { get; set; }
    public string? ObjChannel { get; set; }
    public SortedDictionary<string, float[][]> Channels { get; set; } =
        new(StringComparer.Ordinal);
}

sealed class MaterialCatalog
{
    public string Name { get; set; } = "";
    public string? ShaderArchive { get; set; }
    public string? ShadingModel { get; set; }
    public string[] TextureRefs { get; set; } = [];
    public string[] Samplers { get; set; } = [];
    public string[] ShaderParams { get; set; } = [];
    public string[] RenderInfos { get; set; } = [];
}

sealed class BoneCatalog
{
    public string Name { get; set; } = "";
    public short ParentIndex { get; set; }
    public float[] Position { get; set; } = [];
    public float[] Rotation { get; set; } = [];
    public float[] Scale { get; set; } = [];
    public short SmoothMatrixIndex { get; set; }
    public short RigidMatrixIndex { get; set; }
    public string RotationMode { get; set; } = "";
}

sealed class MaterialCatalogTotals
{
    public int ResourceCount { get; set; }
    public long SourceByteCount { get; set; }
    public int ModelCount { get; set; }
    public int ShapeCount { get; set; }
    public int MaterialCount { get; set; }
    public int TextureAssignmentCount { get; set; }
    public int SamplerStateCount { get; set; }
    public int AttributeAssignmentCount { get; set; }
    public int SamplerAssignmentCount { get; set; }
    public int ShaderOptionCount { get; set; }
    public int ShaderParameterCount { get; set; }
    public int RenderInfoCount { get; set; }
}

sealed class AnimationResourceCatalog
{
    public string Source { get; set; } = "";
    public string ResourceName { get; set; } = "";
    public long ByteLength { get; set; }
    public string Sha256 { get; set; } = "";
    public List<SkeletalAnimationCatalog> SkeletalAnimations { get; } = [];
}

sealed class SkeletalAnimationCatalog
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public int FrameCount { get; set; }
    public bool Loop { get; set; }
    public bool Baked { get; set; }
    public string RotationMode { get; set; } = "";
    public string ScaleMode { get; set; } = "";
    public string[] BoneNames { get; set; } = [];
    public int CurveCount { get; set; }
}

sealed class SkeletalAnimationDump
{
    public string Source { get; set; } = "";
    public long SourceByteLength { get; set; }
    public string SourceSha256 { get; set; } = "";
    public string ResourceName { get; set; } = "";
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public int FrameCount { get; set; }
    public bool Loop { get; set; }
    public bool Baked { get; set; }
    public string RotationMode { get; set; } = "";
    public string ScaleMode { get; set; } = "";
    public List<BoneAnimationDump> Bones { get; } = [];
}

sealed class BoneAnimationDump
{
    public int Index { get; set; }
    public string Name { get; set; } = "";
    public ushort BindIndex { get; set; }
    public string BaseFlags { get; set; } = "";
    public string CurveFlags { get; set; } = "";
    public string TransformFlags { get; set; } = "";
    public float[] BaseScale { get; set; } = [];
    public float[] BaseRotation { get; set; } = [];
    public float[] BaseTranslation { get; set; } = [];
    public List<AnimationCurveDump> Curves { get; } = [];
}

sealed class AnimationCurveDump
{
    public uint DataOffset { get; set; }
    public string Type { get; set; } = "";
    public float StartFrame { get; set; }
    public float EndFrame { get; set; }
    public float Scale { get; set; }
    public float Offset { get; set; }
    public float Delta { get; set; }
    public float[] Frames { get; set; } = [];
    public float[][] Keys { get; set; } = [];
}
