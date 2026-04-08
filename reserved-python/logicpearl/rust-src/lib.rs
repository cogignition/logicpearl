use logicpearl_core::LogicPearlError;
use logicpearl_engine::LogicPearlEngine;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyModule, PyType};
use serde::Serialize;
use serde_json::Value;

#[pyclass(name = "LogicPearlEngine")]
struct PyLogicPearlEngine {
    inner: LogicPearlEngine,
}

#[pymethods]
impl PyLogicPearlEngine {
    #[classmethod]
    fn from_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[classmethod]
    fn from_artifact_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_artifact_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[classmethod]
    fn from_pipeline_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_pipeline_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[getter]
    fn kind(&self) -> String {
        serde_json::to_string(&self.inner.kind())
            .ok()
            .and_then(|text| serde_json::from_str::<String>(&text).ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[getter]
    fn source_path(&self) -> String {
        self.inner.source_path().display().to_string()
    }

    fn run(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let input = py_any_to_json(input)?;
        let result = self
            .inner
            .run_json_value(&input)
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }

    fn run_single(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let input = py_any_to_json(input)?;
        let result = self
            .inner
            .run_single_json(&input)
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }

    fn run_batch(&self, py: Python<'_>, inputs: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let value = py_any_to_json(inputs)?;
        let items = value.as_array().ok_or_else(|| {
            PyValueError::new_err("run_batch expects a JSON-compatible Python list")
        })?;
        let result = self
            .inner
            .run_batch_json(items)
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }
}

#[pyfunction]
fn load_engine(path: &str) -> PyResult<PyLogicPearlEngine> {
    Ok(PyLogicPearlEngine {
        inner: LogicPearlEngine::from_path(path).map_err(to_py_runtime_error)?,
    })
}

#[pymodule]
fn _logicpearl(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<PyLogicPearlEngine>()?;
    module.add_function(wrap_pyfunction!(load_engine, module)?)?;

    let doc = "Python bindings for logicpearl-engine.";
    module.add("__doc__", doc)?;
    let _ = py;
    Ok(())
}

fn py_any_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    let py = value.py();
    let json = PyModule::import(py, "json")?;
    let text: String = json.getattr("dumps")?.call1((value,))?.extract()?;
    serde_json::from_str(&text)
        .map_err(|err| PyValueError::new_err(format!("input must be JSON-compatible: {err}")))
}

fn serialize_to_python(py: Python<'_>, value: &impl Serialize) -> PyResult<PyObject> {
    let json = PyModule::import(py, "json")?;
    let text = serde_json::to_string(value).map_err(|err| {
        PyRuntimeError::new_err(format!("failed to serialize LogicPearl result: {err}"))
    })?;
    Ok(json.getattr("loads")?.call1((text,))?.unbind())
}

fn to_py_runtime_error(err: LogicPearlError) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("package should live under logicpearl/reserved-python/logicpearl")
            .to_path_buf()
    }

    #[test]
    fn wrapper_reports_pipeline_kind() {
        let pipeline =
            repo_root().join("examples/pipelines/observer_membership_verify/pipeline.json");
        let engine = PyLogicPearlEngine {
            inner: LogicPearlEngine::from_path(&pipeline).expect("pipeline should load"),
        };
        assert_eq!(engine.kind(), "pipeline");
        assert!(engine.source_path().ends_with("pipeline.json"));
    }

    #[test]
    fn converts_python_input_to_json_value() {
        Python::with_gil(|py| {
            let payload = PyDict::new(py);
            payload
                .set_item("member", true)
                .expect("python dict should accept bool");
            payload
                .set_item("age", 34)
                .expect("python dict should accept integer");
            payload
                .set_item("country", "US")
                .expect("python dict should accept string");

            let value = py_any_to_json(payload.as_any()).expect("python payload should convert");
            assert_eq!(
                value,
                json!({
                    "member": true,
                    "age": 34,
                    "country": "US"
                })
            );
        });
    }
}
