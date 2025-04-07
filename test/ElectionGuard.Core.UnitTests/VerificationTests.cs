﻿using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;

namespace ElectionGuard.Core.UnitTests;

public class VerificationTests
{
    [Fact]
    public void Verification1_PassesCorrectly()
    {
        var cryptographicParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);

        ParameterVerification validation = new ParameterVerification();

        Exception exception = Record.Exception(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Null(exception);
    }

    [Fact]
    public void Verification1_FailsWhenVersionIsDifferent()
    {
        var expectedParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(expectedParameters, guardianParameters);

        var cryptographicParameters = new CryptographicParameters(
            "v2.0.0",
            CryptographicParameters.Q_DEFAULT_HEX,
            CryptographicParameters.P_DEFAULT_HEX,
            CryptographicParameters.R_DEFAULT_HEX,
            CryptographicParameters.G_DEFAULT_HEX);

        ParameterVerification validation = new ParameterVerification();

        VerificationFailedException exception = Assert.Throws<VerificationFailedException>(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Equal("1.A", exception.SubSection);
    }

    [Fact]
    public void Verification1_FailsWhenPIsDifferent()
    {
        var expectedParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(expectedParameters, guardianParameters);

        var cryptographicParameters = new CryptographicParameters(
            CryptographicParameters.VERSION_DEFAULT,
            CryptographicParameters.Q_DEFAULT_HEX,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0",
            CryptographicParameters.R_DEFAULT_HEX,
            CryptographicParameters.G_DEFAULT_HEX);

        ParameterVerification validation = new ParameterVerification();

        VerificationFailedException exception = Assert.Throws<VerificationFailedException>(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Equal("1.B", exception.SubSection);
    }

    [Fact]
    public void Verification1_FailsWhenQIsDifferent()
    {
        var expectedParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(expectedParameters, guardianParameters);

        var cryptographicParameters = new CryptographicParameters(
            CryptographicParameters.VERSION_DEFAULT,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40",
            CryptographicParameters.P_DEFAULT_HEX,
            CryptographicParameters.R_DEFAULT_HEX,
            CryptographicParameters.G_DEFAULT_HEX);

        ParameterVerification validation = new ParameterVerification();

        VerificationFailedException exception = Assert.Throws<VerificationFailedException>(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Equal("1.C", exception.SubSection);
    }

    [Fact]
    public void Verification1_FailsWhenGIsDifferent()
    {
        var expectedParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(expectedParameters, guardianParameters);

        var cryptographicParameters = new CryptographicParameters(
            CryptographicParameters.VERSION_DEFAULT,
            CryptographicParameters.Q_DEFAULT_HEX,
            CryptographicParameters.P_DEFAULT_HEX,
            CryptographicParameters.R_DEFAULT_HEX,
            "36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE00");
        
        ParameterVerification validation = new ParameterVerification();

        VerificationFailedException exception = Assert.Throws<VerificationFailedException>(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Equal("1.D", exception.SubSection);
    }

    [Fact]
    public void Verification1_FailsWhenParameterBaseHashIsDifferent()
    {
        var cryptographicParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);

        ParameterVerification validation = new ParameterVerification();

        byte[] baseHash = EGParameters.ParameterBaseHash;
        baseHash[baseHash.Length - 1] = 0;

        VerificationFailedException exception = Assert.Throws<VerificationFailedException>(() => validation.Verify(cryptographicParameters, guardianParameters, EGParameters.ParameterBaseHash));
        Assert.Equal("1.E", exception.SubSection);
    }
}
