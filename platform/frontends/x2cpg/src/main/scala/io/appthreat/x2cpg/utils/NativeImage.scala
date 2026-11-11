package io.appthreat.x2cpg.utils

/** Facts about the GraalVM native image this code may be running in. */
object NativeImage:

  /** Whether this code runs inside a native image, as `ImageInfo.inImageRuntimeCode()` reports it.
    * A `def`: the frontends' objects are initialised while the image is built, and a value computed
    * then would be baked in.
    */
  def inImage: Boolean = sys.props.get("org.graalvm.nativeimage.imagecode").contains("runtime")
