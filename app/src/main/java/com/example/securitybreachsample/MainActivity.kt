package com.example.securitybreachsample

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.securitybreachsample.jailbreak.AppDeviceSecurityCheck
import com.example.securitybreachsample.ui.theme.SecuritybreachsampleTheme


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        enableEdgeToEdge()
        setContent {
            var selectedItem by remember { mutableStateOf(false) }
            SecuritybreachsampleTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .fillMaxHeight()
                            .padding(innerPadding),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {

                        Button(onClick = {
//                            val data = AppDeviceSecurityCheck.instance.isInstalledFromPlayStore(context = this@MainActivity)
                            val data2 = AppDeviceSecurityCheck.instance.isAppSignatureValid(this@MainActivity)
//                            Log.d("ahsdg", "${sigs.hashCode()}")
                            selectedItem= data2
                            Log.d("ahsdg", "$data2")

                        }, modifier = Modifier) {
                            Text(text = "Check Status")
                        }
                        Text(text = "$selectedItem")
                    }
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    SecuritybreachsampleTheme {
        Greeting("Android")
    }
}