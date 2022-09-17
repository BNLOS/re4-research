The names of each shader file go with the g_XXXShaders array in the IDA database
(`g_MiscPixelShaders` / `g_MiscVertexShaders` / `g_ModelPixelShaders` / `g_ModelVertexShaders`)

This array is only used by the D3D side of the GX code, the game code itself calls into the `GXCallShader` function, which queues itself up and then runs the `D3D_ShaderXX` func based on the parameter to it.
Finally the `D3D_ShaderXX` func indexes into the `g_XXXShaders` array, you can find which index by checking that func.
