package com.rumblefish.kotlinrumbleapp

import android.app.Dialog
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button

class SecondActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_second)

        val btnShowDialog: Button = findViewById(R.id.btnShowModal)

        btnShowDialog.setOnClickListener {
            showDialogWithBottomAnimation()
        }
    }

    private fun showDialogWithBottomAnimation() {
        val dialog = Dialog(this)
        dialog.setContentView(R.layout.dialog_custom)

        dialog.window?.setGravity(Gravity.BOTTOM)
        dialog.window?.setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
        dialog.window?.attributes?.windowAnimations = R.style.DialogAnimation

        val btnAccept: Button = dialog.findViewById(R.id.btnOption1)
        val btnCancel: Button = dialog.findViewById(R.id.btnOption2)

        btnAccept.setOnClickListener {
            println("Hello, World!")
            dialog.dismiss()
        }

        btnCancel.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()
    }
}