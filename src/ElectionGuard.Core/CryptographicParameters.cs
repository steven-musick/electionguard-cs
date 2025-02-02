﻿using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core;

public static class EGParameters
{
    public static void Init(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        _cryptographicParameters = cryptographicParameters;
        _guardianParameters = guardianParameters;
        _parameterBaseHash = new ParameterBaseHash(CryptographicParameters, GuardianParameters);
    }

    private static CryptographicParameters? _cryptographicParameters;
    public static CryptographicParameters CryptographicParameters => _cryptographicParameters ?? throw new Exception("EGParameters not initialized.");

    private static GuardianParameters? _guardianParameters;
    public static GuardianParameters GuardianParameters => _guardianParameters ?? throw new Exception("EGParameters not initialized.");

    private static ParameterBaseHash? _parameterBaseHash;
    public static ParameterBaseHash ParameterBaseHash => _parameterBaseHash ?? throw new Exception("EGParameters not initialized.");
}

public class CryptographicParameters
{
    public const string VERSION_DEFAULT = "v2.1.0";
    public const string Q_DEFAULT_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
    public const string P_DEFAULT_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    public const string R_DEFAULT_HEX = "0100000000000000000000000000000000000000000000000000000000000000BCB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAB857AE8F428165418806C62B0EA36355A3A73E0C741985BF6A0E3130179BF2F0B43E33AD862923861B8C9F768C4169519600BAD06093F964B27E02D86831231A9160DE48F4DA53D8AB5E69E386B694BEC1AE722D47579249D5424767C5C33B9151E07C5C11D106AC446D330B47DB59D352E47A53157DE04461900F6FE360DB897DF5316D87C94AE71DAD0BE84B647C4BCF818C23A2D4EBB53C702A5C8062D19F5E9B5033A94F7FF732F54129712869D97B8C96C412921A9D8679770F499A041C297CFF79D4C9149EB6CAF67B9EA3DC563D965F3AAD1377FF22DE9C3E62068DD0ED6151C37B4F74634C2BD09DA912FD599F4333A8D2CC005627DCA37BAD43E64A3963119C0BFE34810A21EE7CFC421D53398CBC7A95B3BF585E5A04B790E2FE1FE9BC264FDA8109F6454A082F5EFB2F37EA237AA29DF320D6EA860C41A9054CCD24876C6253F667BFB0139B5531FF30189961202FD2B0D55A75272C7FD73343F7899BCA0B36A4C470A64A009244C84E77CEBC92417D5BB13BF18167D8033EB6C4DD7879FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F529FD4A7F52A";
    public const string G_DEFAULT_HEX = "36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE0F";

    public CryptographicParameters()
    {
        Version = new Version(VERSION_DEFAULT);

        Q = new BigInteger(Convert.FromHexString(Q_DEFAULT_HEX), true, true);
        P = new BigInteger(Convert.FromHexString(P_DEFAULT_HEX), true, true);
        R = new BigInteger(Convert.FromHexString(R_DEFAULT_HEX), true, true);
        G = new BigInteger(Convert.FromHexString(G_DEFAULT_HEX), true, true);
    }

    public CryptographicParameters(string version, string q, string p, string r, string g)
    {
        Version = new Version(version);
        Q = new BigInteger(Convert.FromHexString(q), true, true);
        P = new BigInteger(Convert.FromHexString(p), true, true);
        R = new BigInteger(Convert.FromHexString(r), true, true);
        G = new BigInteger(Convert.FromHexString(g), true, true);
    }

    public Version Version { get; }

    public BigInteger Q { get; }
    public BigInteger P { get; }
    public BigInteger R { get; }
    public BigInteger G { get; }
}

public class Version : IEquatable<Version?>
{
    public Version(string version)
    {
        _version = version;
    }

    private readonly string _version;

    public override string ToString()
    {
        return _version;
    }

    public override bool Equals(object? obj)
    {
        return Equals(obj as Version);
    }

    public bool Equals(Version? other)
    {
        return other is not null &&
               _version == other._version;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_version);
    }

    public static implicit operator string(Version version)
    {
        return version._version;
    }

    public static implicit operator byte[](Version version)
    {
        return System.Text.Encoding.UTF8.GetBytes(version._version).PadToLength(32);
    }

    public static bool operator ==(Version? left, Version? right)
    {
        return EqualityComparer<Version>.Default.Equals(left, right);
    }

    public static bool operator !=(Version? left, Version? right)
    {
        return !(left == right);
    }
}

public class GuardianParameters
{
    public int N { get; } = 5;
    public int K { get; } = 3;
}

public abstract class HashValue
{
    protected abstract byte[] Bytes { get; }

    public static implicit operator byte[](HashValue value)
    {
        return value.Bytes;
    }
}

public class ParameterBaseHash : HashValue
{
    public ParameterBaseHash(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        Bytes = EGHash.Hash(cryptographicParameters.Version,
            [0x00],
            cryptographicParameters.P.ToByteArray(),
            cryptographicParameters.Q.ToByteArray(),
            cryptographicParameters.G.ToByteArray(),
            guardianParameters.N.ToByteArray(),
            guardianParameters.K.ToByteArray());
    }

    protected override byte[] Bytes { get; }
}

public class ManifestFile
{
    public required byte[] Bytes { get; init; }
}

public class ElectionBaseHash : HashValue
{
    public ElectionBaseHash(ParameterBaseHash parameterBaseHash, ManifestFile manifestFile)
    {
        Bytes = EGHash.Hash(parameterBaseHash,
            [0x01],
            manifestFile.Bytes
            );
    }

    protected override byte[] Bytes { get; }
}